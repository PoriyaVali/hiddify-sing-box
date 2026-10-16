//go:build linux || darwin

package anytls

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// upstream wraps a conn the way sing-box's dialers do.
type upstream struct{ net.Conn }

func (w upstream) Upstream() any { return w.Conn }

// tlsLike wraps a conn the way sing's TLS conns do.
type tlsLike struct{ net.Conn }

func (w tlsLike) NetConn() net.Conn { return w.Conn }

func notSent(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// The session's socket, under the TLS conn and the dialers' wrappers around
// it, must hold no more than notSentLowat bytes unsent.
func TestLimitUnsentReachesTheSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"bare":            func(c net.Conn) net.Conn { return c },
		"dialer wrappers": func(c net.Conn) net.Conn { return upstream{upstream{c}} },
		"TLS over a dialer wrapper": func(c net.Conn) net.Conn {
			return tlsLike{upstream{c}}
		},
	} {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		limitUnsent(wrap(c))
		if got := notSent(t, c.(*net.TCPConn)); got != notSentLowat {
			t.Fatalf("%s: TCP_NOTSENT_LOWAT = %d, want %d", name, got, notSentLowat)
		}
		c.Close()
	}
}
