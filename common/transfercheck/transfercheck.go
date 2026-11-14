// Package transfercheck verifies that an outbound really carries data both
// ways (Doctor Mobile).
//
// A URL test proves a node answers one small GET. Nodes that pass it but stall
// every upload are common on filtered networks - a censor that throttles the
// upstream direction, a server whose uplink is saturated - and a group that
// picks by URL-test delay alone keeps choosing them: pages start loading and
// then every form, upload and message send hangs.
//
// The probe is the same contract as the mihomo core's transfer check, so one
// endpoint serves both cores: POST 64 KiB of random bytes over HTTPS through
// the outbound, and accept only a 200 that names the exact byte count and
// SHA-256 of what was sent and returns exactly 128 KiB.
package transfercheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	UploadBytes   = 64 * 1024
	DownloadBytes = 2 * UploadBytes

	// ProbeTimeout bounds one attempt against one endpoint.
	ProbeTimeout = 7 * time.Second
)

// ValidateEndpoints accepts one or two plain HTTPS URLs, as mihomo does.
func ValidateEndpoints(endpoints []string) error {
	if len(endpoints) < 1 || len(endpoints) > 2 {
		return errors.New("transfer check needs one or two HTTPS endpoints")
	}
	for _, raw := range endpoints {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid transfer check endpoint: " + raw)
		}
	}
	return nil
}

// Check tries each endpoint in turn and returns nil once one verifies the
// exchange through dialer.
func Check(ctx context.Context, dialer N.Dialer, endpoints []string, roots *tls.Config) error {
	var last error
	for _, endpoint := range endpoints {
		probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
		last = probe(probeCtx, dialer, endpoint, roots)
		cancel()
		if last == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return last
}

func probe(ctx context.Context, dialer N.Dialer, endpoint string, roots *tls.Config) error {
	payload := make([]byte, UploadBytes)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if roots != nil {
		tlsConfig = roots.Clone()
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
		},
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 4 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("upload: " + err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("status " + strconv.Itoa(response.StatusCode))
	}
	if response.Header.Get("X-DM-Upload-Bytes") != strconv.Itoa(UploadBytes) ||
		response.Header.Get("X-DM-Upload-SHA256") != hex.EncodeToString(digest[:]) {
		return errors.New("the endpoint did not receive the upload intact")
	}
	if response.Header.Get("Content-Encoding") != "" {
		return errors.New("compressed download")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, DownloadBytes+1))
	if err != nil {
		return errors.New("download: " + err.Error())
	}
	if len(body) != DownloadBytes {
		return errors.New("download: " + strconv.Itoa(len(body)) + " bytes")
	}
	return nil
}

// Status of one outbound's last check.
type Status int

const (
	Unknown Status = iota
	Healthy
	Failed
)

const (
	// A verified outbound is checked again after RecheckAfter, when it is
	// still the one being picked; a failure may be retried after RetryAfter.
	RecheckAfter = 15 * time.Minute
	RetryAfter   = time.Minute
	// A failure stops counting after FailedFor, so a node that recovered is
	// not held down for the rest of the session.
	FailedFor = 30 * time.Minute
)

// State is one outbound's record. It is not safe for concurrent use; the
// caller holds its own lock.
type State struct {
	Status    Status
	CheckedAt time.Time
	Running   bool
}

// Due reports whether a new check should start now.
func (s *State) Due(now time.Time) bool {
	if s.Running {
		return false
	}
	switch s.Status {
	case Healthy:
		return now.Sub(s.CheckedAt) >= RecheckAfter
	case Failed:
		return now.Sub(s.CheckedAt) >= RetryAfter
	}
	return true
}

// FailedNow reports whether the outbound should be ranked as unable to carry
// data in both directions.
func (s *State) FailedNow(now time.Time) bool {
	return s.Status == Failed && now.Sub(s.CheckedAt) < FailedFor
}
