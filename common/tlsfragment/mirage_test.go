package tf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// captureConn records what was written and how many Write calls it took, so the
// test can assert the exact wire shape (both records in ONE segment).
type captureConn struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

// TestMirageShape locks in the shape measured to defeat Iran's SNI-DPI:
// exactly two TLS records written in a single TCP segment, where the first
// record ends before the SNI and the second still contains it intact.
func TestMirageShape(t *testing.T) {
	t.Parallel()
	hello := makeClientHello("www.instagram.com")
	cap := &captureConn{}
	conn := NewMirageConn(cap, 0)

	n, err := conn.Write(hello)
	require.NoError(t, err)
	require.Equal(t, len(hello), n, "Write must report the caller's length")
	require.Equal(t, 1, cap.writes, "both records must go out in one segment")

	records := splitRecords(t, cap.buf.Bytes())
	require.Len(t, records, 2, "expected exactly two TLS records")

	require.Equal(t, mirageDefaultOffset, len(records[0]),
		"first record must be the small pre-SNI slice")
	require.NotContains(t, string(records[0]), "www.instagram.com",
		"the SNI must NOT be in the first record - that is the whole point")
	require.Contains(t, string(records[1]), "www.instagram.com",
		"the SNI must stay intact in the second record; splitting inside it was measured to be dropped")

	// The concatenated records must reproduce the original handshake byte for byte.
	require.Equal(t, hello[recordHeaderLen:], append(records[0], records[1]...))
}

// TestMirageNonClientHelloUntouched makes sure ordinary traffic is not rewritten.
func TestMirageNonClientHelloUntouched(t *testing.T) {
	t.Parallel()
	payload := []byte("not a tls handshake at all")
	cap := &captureConn{}
	conn := NewMirageConn(cap, 0)

	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.Equal(t, payload, cap.buf.Bytes())

	// Subsequent writes always pass through untouched.
	cap.buf.Reset()
	_, err = conn.Write([]byte("second"))
	require.NoError(t, err)
	require.Equal(t, []byte("second"), cap.buf.Bytes())
}

func splitRecords(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		require.GreaterOrEqual(t, len(b), recordHeaderLen, "truncated record header")
		require.Equal(t, byte(0x16), b[0], "expected a handshake record")
		length := int(binary.BigEndian.Uint16(b[3:5]))
		require.GreaterOrEqual(t, len(b), recordHeaderLen+length, "truncated record body")
		out = append(out, b[recordHeaderLen:recordHeaderLen+length])
		b = b[recordHeaderLen+length:]
	}
	return out
}

// makeClientHello builds a minimal but structurally valid ClientHello record
// carrying the given SNI, mirroring the probe used for the live measurements.
func makeClientHello(sni string) []byte {
	name := []byte(sni)
	var sniExt []byte
	sniExt = append(sniExt, 0x00, 0x00)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(name)+5))
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(name)+3))
	sniExt = append(sniExt, 0x00)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(name)))
	sniExt = append(sniExt, name...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, bytes.Repeat([]byte{0x41}, 32)...) // random
	body = append(body, 0x00)                              // empty session id
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00) // null compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(sniExt)))
	body = append(body, sniExt...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}
