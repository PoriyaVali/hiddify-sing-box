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

// MirageConn splits the first ClientHello into two TLS records, EACH IN ITS OWN
// WRITE.
//
// ⚠️ The separate writes are the load-bearing part and must not be merged back
// into one buffer for tidiness. Until 2026-09-09 both records went out in a
// single write, and Hamrah-e Aval began dropping exactly that form in silence.
//
// Measured that evening on a rooted handset on MCI LTE with this core's own
// uTLS Chrome fingerprint, against 1.1.1.1:443 with the genuinely blocked name
// instagram.com. A shape that REACHES there has evaded; the untouched control
// is reset, which is what proves the censor is still watching. Three rounds,
// order rotated, 15 s between every attempt so the burst penalty below could
// not contaminate it:
//
//	untouched (control)          0 reached, 3 reset
//	two records, ONE write       0 reached, 3 dropped in silence
//	two records, two writes      3 reached  (identical at 0, 5, 20 and 50 ms)
//	three records, three writes  3 reached
//	two records, split at 64     3 reached
//
// The same pattern held against our own REALITY node on 8443. And the sibling
// implementation in mihomo, with the old single-write form, could not complete
// ONE session on that carrier: a capture started before the process caught 69
// flows, all 69 beginning with the 5-byte first record, none receiving a single
// byte. Rebuilt with two writes, the same core on the same carrier: 52 flows,
// 52 replies, zero failures.
//
// Two consequences worth keeping:
//
//   - The gap between writes does nothing. Zero milliseconds behaved exactly
//     like fifty, so there is no sleep here to pay for or to fingerprint.
//   - Six shapes passed, not one. The split point and the record count are both
//     free variables, which is what makes the next block survivable.
//
// 🔑 That censor also PUNISHES bursts: six fragmented attempts back to back once
// made plain TCP fail eight times running for about a minute. Any measurement
// taken from closely spaced attempts records the penalty as well as the shape.
//
// ⚠️ Measured on MCI only. An August measurement on Irancell found the exact
// opposite, and whether that is a carrier difference or a change over time is
// NOT established. Neither form is universal; this is why the offset is meant
// to be steerable from the panel rather than settled here.
type MirageConn struct {
	net.Conn
	offset       int
	records      int
	coalesce     bool
	firstWritten bool
}

// NewMirageConn wraps conn. A records count of 0 or 1 means the measured
// default of two; coalesce restores the single-write form, which one carrier
// drops and another accepts.
func NewMirageConn(conn net.Conn, offset, records int, coalesce bool) *MirageConn {
	if offset <= 0 {
		offset = mirageDefaultOffset
	}
	if records < 2 {
		records = 2
	}
	return &MirageConn{Conn: conn, offset: offset, records: records, coalesce: coalesce}
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
	parts := [][]byte{
		appendRecord(nil, b[:3], handshake[:split]),
		appendRecord(nil, b[:3], handshake[split:]),
	}
	// Extra records are carved out of the tail, AFTER the server name: a cut
	// inside the name is the one shape measured to be dropped even for a
	// hostname that is otherwise allowed.
	for len(parts) < c.records {
		tail := parts[len(parts)-1]
		body := tail[recordHeaderLen:]
		if len(body) < 2 {
			break
		}
		at := len(body) / 2
		parts = parts[:len(parts)-1]
		parts = append(parts,
			appendRecord(nil, tail[:3], body[:at]),
			appendRecord(nil, tail[:3], body[at:]))
	}

	// One write per record. See the type comment: concatenating them is the
	// form this censor drops. The panel can ask for the old shape back.
	if c.coalesce {
		var all []byte
		for _, r := range parts {
			all = append(all, r...)
		}
		if _, err := c.Conn.Write(all); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	for _, r := range parts {
		if _, err := c.Conn.Write(r); err != nil {
			return 0, err
		}
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
