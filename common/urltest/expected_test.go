package urltest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"net/http"
	"testing"
	"time"
)

type responseDialer struct {
	status int
	calls  int
}

func (d *responseDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls++
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		_, _ = fmt.Fprintf(server, "HTTP/1.1 %d Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", d.status)
	}()
	return client, nil
}
func (d *responseDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}
func TestExpectedStatusIsPerCall(t *testing.T) {
	for _, status := range []int{204, 302, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			d := &responseDialer{status: status}
			_, err := URLTestExpected(context.Background(), "http://example.test/", d, 204)
			if (err == nil) != (status == 204) {
				t.Fatalf("status=%d err=%v", status, err)
			}
			if d.calls != 1 {
				t.Fatal("unexpected retry")
			}
		})
	}
}
func TestLegacyStatusSemanticsRemain(t *testing.T) {
	if _, err := URLTest(context.Background(), "http://example.test/", &responseDialer{status: 403}); err != nil {
		t.Fatal(err)
	}
}
func TestCancelledProbeCannotReportSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &responseDialer{status: 204}
	_, err := URLTestExpected(ctx, "http://example.test/", d, 204)
	if !errors.Is(err, context.Canceled) || d.calls != 0 {
		t.Fatalf("cancel ignored: calls=%d err=%v", d.calls, err)
	}
}
