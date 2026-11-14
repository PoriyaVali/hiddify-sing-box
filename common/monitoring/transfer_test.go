package monitoring

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/transfercheck"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// fakeOutbound dials directly; brokenUplink makes every write after the
// first 4 KiB fail, as on a node that answers small requests but cannot
// upload.
type fakeOutbound struct {
	tag          string
	brokenUplink bool
}

func (f *fakeOutbound) Type() string           { return "fake" }
func (f *fakeOutbound) Tag() string            { return f.tag }
func (f *fakeOutbound) Network() []string      { return []string{"tcp"} }
func (f *fakeOutbound) Dependencies() []string { return nil }
func (f *fakeOutbound) DisplayType() string    { return "fake" }
func (f *fakeOutbound) IsReady() bool          { return true }

func (f *fakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, destination.String())
	if err != nil || !f.brokenUplink {
		return conn, err
	}
	return &cutUplink{Conn: conn, left: 4 << 10}, nil
}

func (f *fakeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no udp")
}

type cutUplink struct {
	net.Conn
	left int
}

func (c *cutUplink) Write(b []byte) (int, error) {
	if len(b) > c.left {
		c.Conn.Close()
		return 0, errors.New("uplink reset")
	}
	c.left -= len(b)
	return c.Conn.Write(b)
}

func transferEndpoint(t *testing.T) (*httptest.Server, *tls.Config) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		w.Header().Set("X-DM-Upload-Bytes", strconv.Itoa(len(body)))
		w.Header().Set("X-DM-Upload-SHA256", hex.EncodeToString(digest[:]))
		_, _ = w.Write(make([]byte, transfercheck.DownloadBytes))
	}))
	t.Cleanup(server.Close)
	return server, server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
}

func testMonitor(t *testing.T, endpoint string, roots *tls.Config, outbounds ...*fakeOutbound) *OutboundMonitoring {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := &OutboundMonitoring{
		ctx:               ctx,
		cancel:            cancel,
		logger:            log.NewNOPFactory().Logger(),
		outbounds:         map[string]*outboundState{},
		groups:            map[string]*groupState{},
		transferEndpoints: []string{endpoint},
		transferSlots:     make(chan struct{}, 4),
		transferRoots:     roots,
	}
	for _, outbound := range outbounds {
		m.outbounds[outbound.tag] = &outboundState{
			outbound: outbound,
			history:  adapter.URLTestHistory{Time: time.Now(), Delay: 100},
		}
	}
	return m
}

func waitChecked(t *testing.T, m *OutboundMonitoring, tag string) transfercheck.Status {
	t.Helper()
	state := m.outbounds[tag]
	require.Eventually(t, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		return !state.transfer.Running && state.transfer.Status != transfercheck.Unknown
	}, 20*time.Second, 10*time.Millisecond)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.transfer.Status
}

func TestTransferFailuresCountOnlyOnceTheEndpointAnswers(t *testing.T) {
	t.Parallel()
	server, roots := transferEndpoint(t)
	m := testMonitor(t, server.URL, roots,
		&fakeOutbound{tag: "no-upload", brokenUplink: true},
		&fakeOutbound{tag: "good"},
	)

	m.VerifyTransfer("no-upload")
	require.Equal(t, transfercheck.Failed, waitChecked(t, m, "no-upload"))
	require.False(t, m.getUrlTest("no-upload").TransferFailed,
		"before any node passes, a failure may be the endpoint's: it must not move the group")

	m.VerifyTransfer("good")
	require.Equal(t, transfercheck.Healthy, waitChecked(t, m, "good"))
	require.True(t, m.getUrlTest("no-upload").TransferFailed, "once the endpoint is proven, the node that cannot upload is marked")
	require.False(t, m.getUrlTest("good").TransferFailed)
}

func TestTransferCheckSkipsDeadNodesAndRunsOncePerWindow(t *testing.T) {
	t.Parallel()
	server, roots := transferEndpoint(t)
	m := testMonitor(t, server.URL, roots, &fakeOutbound{tag: "dead"}, &fakeOutbound{tag: "good"})
	m.outbounds["dead"].history.Delay = TimeoutDelay

	m.VerifyTransfer("dead")
	m.VerifyTransfer("good")
	require.Equal(t, transfercheck.Healthy, waitChecked(t, m, "good"))
	require.Equal(t, transfercheck.Unknown, m.outbounds["dead"].transfer.Status, "a node that failed its URL test is not probed")

	checkedAt := m.outbounds["good"].transfer.CheckedAt
	m.VerifyTransfer("good")
	time.Sleep(50 * time.Millisecond)
	m.outbounds["good"].mu.Lock()
	defer m.outbounds["good"].mu.Unlock()
	require.Equal(t, checkedAt, m.outbounds["good"].transfer.CheckedAt, "a verified node is not probed again within the recheck window")
}

func TestTransferCheckOffWithoutEndpoints(t *testing.T) {
	t.Parallel()
	m := testMonitor(t, "", nil, &fakeOutbound{tag: "a"})
	m.transferEndpoints = nil
	m.VerifyTransfer("a")
	require.Equal(t, transfercheck.Unknown, m.outbounds["a"].transfer.Status)
	require.False(t, m.getUrlTest("a").TransferFailed)
}
