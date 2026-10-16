//go:build linux || darwin

package anytls

import (
	"net"

	"golang.org/x/sys/unix"
)

// notSentLowat caps the bytes a session's TCP socket may hold unsent.
//
// Every stream of a pooled session shares one TCP connection. Without a cap,
// the kernel takes all an upload hands it - up to the send buffer, a megabyte
// or more on Android - and when the user cancels, the stream closes but that
// data still has to leave over the uplink. The session goes back to the pool,
// and the next request's SYN waits behind seconds of a dead upload: on a weak
// link its acknowledgement does not come in time, the session is closed and
// the request fails. With the cap the rest of an upload waits in the session,
// which drops it when the stream closes. Only unsent bytes are capped, not
// those in flight, so throughput is unchanged. The node uses the same value.
const notSentLowat = 16 << 10

// limitUnsent sets notSentLowat on the TCP socket under conn. The session
// gets a TLS connection: sing's TLS conns lead to the socket through
// NetConn, and the dialers' wrappers through Upstream.
func limitUnsent(conn net.Conn) {
	for i := 0; i < 8 && conn != nil; i++ {
		switch c := conn.(type) {
		case *net.TCPConn:
			if rc, err := c.SyscallConn(); err == nil {
				_ = rc.Control(func(fd uintptr) {
					_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, notSentLowat)
				})
			}
			return
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		case interface{ Upstream() any }:
			conn, _ = c.Upstream().(net.Conn)
		default:
			return
		}
	}
}
