package tf

import (
	"bytes"
	"encoding/binary"
	utls "github.com/metacubex/utls"
	"testing"
)

// Real serialization from each fork's pinned uTLS, without a network or server.
// This is not a REALITY authentication test or a carrier measurement.
func TestMirageRealChromeClientHello(t *testing.T) {
	for _, sni := range []string{"yahoo.com", "cdnjs.cloudflare.com"} {
		for round := 0; round < 20; round++ {
			c := utls.UClient(nil, &utls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}}, utls.HelloChrome_Auto)
			if err := c.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			hello := c.HandshakeState.Hello.Raw
			if len(hello) == 0 {
				t.Fatal("unmarshalled ClientHello")
			}
			record := []byte{22, 3, 1, 0, 0}
			binary.BigEndian.PutUint16(record[3:5], uint16(len(hello)))
			record = append(record, hello...)
			for count := 2; count <= 8; count++ {
				parts, n, ok := mirageParts(record, 5, count)
				if !ok {
					t.Fatal("real Chrome rejected")
				}
				var body []byte
				whole := 0
				for _, p := range parts[:n] {
					body = append(body, p[5:]...)
					if bytes.Contains(p[5:], []byte(sni)) {
						whole++
					}
				}
				if whole != 1 || !bytes.Equal(body, hello) {
					t.Fatalf("corrupt real hello: count=%d", count)
				}
			}
		}
	}
}
