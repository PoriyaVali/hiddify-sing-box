package transfercheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// directDialer stands in for an outbound. limit > 0 stalls every connection
// after that many bytes have been written - an uplink that is throttled to
// nothing while downloads still work.
type directDialer struct {
	limit int
	dials atomic.Int32
}

func (d *directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, destination.String())
	if err != nil || d.limit <= 0 {
		return conn, err
	}
	return &stallingConn{Conn: conn, left: d.limit, closed: make(chan struct{})}, nil
}

func (d *directDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type stallingConn struct {
	net.Conn
	left      int
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stallingConn) Write(b []byte) (int, error) {
	if c.left <= 0 {
		// Hold the write until the caller gives up and closes the conn.
		<-c.closed
		return 0, net.ErrClosed
	}
	if len(b) > c.left {
		b = b[:c.left]
	}
	c.left -= len(b)
	return c.Conn.Write(b)
}

func (c *stallingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// endpoint behaves like the deployed dm-transfer-v1 script; broken lets a test
// make it lie about one part of the contract.
func endpoint(t *testing.T, broken string) (*httptest.Server, *tls.Config) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		w.Header().Set("X-DM-Upload-Bytes", strconv.Itoa(len(body)))
		w.Header().Set("X-DM-Upload-SHA256", hex.EncodeToString(digest[:]))
		size := DownloadBytes
		switch broken {
		case "digest":
			w.Header().Set("X-DM-Upload-SHA256", "00")
		case "short":
			size = DownloadBytes / 2
		case "status":
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write(make([]byte, size))
	}))
	t.Cleanup(server.Close)
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return server, roots
}

func TestCheckAcceptsOnlyAnExchangeVerifiedBothWays(t *testing.T) {
	t.Parallel()
	server, roots := endpoint(t, "")
	dialer := &directDialer{}
	require.NoError(t, Check(context.Background(), dialer, []string{server.URL}, roots))
	require.EqualValues(t, 1, dialer.dials.Load(), "one connection per check")

	for _, broken := range []string{"digest", "short", "status"} {
		server, roots := endpoint(t, broken)
		require.Error(t, Check(context.Background(), &directDialer{}, []string{server.URL}, roots), broken)
	}
}

// The case the check exists for: downloads work, the upload never gets
// through. A URL test passes on such a node; this must not.
func TestCheckFailsANodeThatCannotUpload(t *testing.T) {
	t.Parallel()
	server, roots := endpoint(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	err := Check(ctx, &directDialer{limit: 4 << 10}, []string{server.URL}, roots)
	require.Error(t, err)
	require.Less(t, time.Since(started), 3*time.Second, "the caller's deadline bounds the check")
}

func TestCheckTriesTheSecondEndpoint(t *testing.T) {
	t.Parallel()
	good, roots := endpoint(t, "")
	dead := "https://127.0.0.1:1/dm-transfer-v1.php"
	require.NoError(t, Check(context.Background(), &directDialer{}, []string{dead, good.URL}, roots))
}

func TestValidateEndpoints(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateEndpoints([]string{"https://ddr.example/dm-transfer-v1.php"}))
	require.NoError(t, ValidateEndpoints([]string{"https://a.example/x", "https://b.example/y"}))
	for _, bad := range [][]string{
		nil,
		{"https://a.example/x", "https://b.example/y", "https://c.example/z"},
		{"http://a.example/x"},
		{"https://user:pw@a.example/x"},
		{"https://a.example/x?token=1"},
		{"https://a.example/x#frag"},
		{"https:///x"},
	} {
		require.Error(t, ValidateEndpoints(bad), "%v", bad)
	}
}

func TestStateTiming(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var s State
	require.True(t, s.Due(now), "an unchecked node is due")
	s.Running = true
	require.False(t, s.Due(now), "never two checks at once")

	s = State{Status: Healthy, CheckedAt: now}
	require.False(t, s.Due(now.Add(RecheckAfter-time.Second)))
	require.True(t, s.Due(now.Add(RecheckAfter)))
	require.False(t, s.FailedNow(now))

	s = State{Status: Failed, CheckedAt: now}
	require.False(t, s.Due(now.Add(RetryAfter-time.Second)))
	require.True(t, s.Due(now.Add(RetryAfter)))
	require.True(t, s.FailedNow(now.Add(FailedFor-time.Second)))
	require.False(t, s.FailedNow(now.Add(FailedFor)), "a failure stops counting after a while")
}
