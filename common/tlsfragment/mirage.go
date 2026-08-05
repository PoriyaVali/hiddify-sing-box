package tf

import (
	"encoding/binary"
	"net"
)

// Mirage — Doctor Mobile's TLS-record fragmentation.
//
// Why this exists next to Conn (the upstream `tls_record_fragment`):
// upstream splits the ClientHello at random positions *inside the SNI hostname
// labels*. Measured against Iran's DPI (2026-08-05, both a datacenter vantage
// and a residential Irancell phone), that shape is DROPPED — even for an
// allowed hostname. What does work, 18/18, is the opposite shape: a small,
// clean FIRST record that ends *before* the SNI, with the SNI left intact in
// the second record. The DPI only parses the first TLS record looking for a
// ClientHello SNI; when the name is not there it stops looking instead of
// reassembling the records, so the connection sails through. The real server
// reassembles the handshake across records normally, as TLS requires.
//
// The consequence that matters for REALITY: because the censor never sees the
// borrowed server name, that name no longer has to be a host that is reachable
// and unblocked from Iran. Picking a borrowed site used to be the hard part
// (a blocked one killed the node); with Mirage the name only has to exist for
// the server's own fallback.
const (
	recordHeaderLen = 5
	// Bytes of the handshake message kept in the first record. 5 = the
	// handshake header (type + 3-byte length) plus one byte, which is always
	// far ahead of the SNI extension and is the shape that was measured.
	mirageDefaultOffset = 5
)

// MirageConn splits the first ClientHello into two TLS records, both written in
// a single TCP segment (record-level only — TCP-level splitting was measured to
// fail here, because this DPI reassembles the TCP stream before matching).
type MirageConn struct {
	net.Conn
	offset       int
	firstWritten bool
}

func NewMirageConn(conn net.Conn, offset int) *MirageConn {
	if offset <= 0 {
		offset = mirageDefaultOffset
	}
	return &MirageConn{Conn: conn, offset: offset}
}

func (c *MirageConn) Write(b []byte) (int, error) {
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true

	split := c.splitPoint(b)
	if split <= 0 {
		// Not a ClientHello we can split safely — send untouched.
		return c.Conn.Write(b)
	}

	handshake := b[recordHeaderLen:]
	first, second := handshake[:split], handshake[split:]

	out := make([]byte, 0, len(b)+recordHeaderLen)
	out = appendRecord(out, b[:3], first)
	out = appendRecord(out, b[:3], second)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// splitPoint returns how many bytes of the handshake message belong in the
// first record, or 0 when the buffer is not a splittable ClientHello.
func (c *MirageConn) splitPoint(b []byte) int {
	if len(b) <= recordHeaderLen+c.offset {
		return 0
	}
	if b[0] != 0x16 { // not a handshake record
		return 0
	}
	// Only fragment when there is actually a server name to hide, and make
	// sure we cut before it — a cut inside the SNI is the shape that fails.
	serverName := IndexTLSServerName(b)
	if serverName == nil {
		return 0
	}
	sniStart := serverName.Index - recordHeaderLen
	split := c.offset
	if split >= sniStart {
		split = sniStart / 2
	}
	if split <= 0 {
		return 0
	}
	return split
}

// appendRecord writes one TLS record: the original 3-byte header prefix
// (content type + legacy version), the payload length, then the payload.
func appendRecord(dst []byte, headerPrefix []byte, payload []byte) []byte {
	dst = append(dst, headerPrefix...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

func (c *MirageConn) ReaderReplaceable() bool {
	return true
}

func (c *MirageConn) WriterReplaceable() bool {
	return c.firstWritten
}

func (c *MirageConn) Upstream() any {
	return c.Conn
}
