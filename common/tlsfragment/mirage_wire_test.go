package tf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

func paddedMirageHello(name string, padding int) []byte {
	b := makeClientHello(name)
	n := int(binary.BigEndian.Uint16(b[50:52]))
	b = append(b, 0, 21, byte(padding>>8), byte(padding))
	b = append(b, make([]byte, padding)...)
	binary.BigEndian.PutUint16(b[50:52], uint16(n+4+padding))
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	n = len(b) - 9
	b[6], b[7], b[8] = byte(n>>16), byte(n>>8), byte(n)
	return b
}
func TestMirageEveryShapeKeepsSNIWhole(t *testing.T) {
	for _, name := range []string{"a.io", strings.Repeat("a", 63) + ".example.test"} {
		for count := 2; count <= 8; count++ {
			for _, offset := range []int{0, 1, 2, 5, 16, 64, 1024, 1 << 30} {
				hello := paddedMirageHello(name, 96)
				parts, n, ok := mirageParts(hello, offset, count)
				if !ok || n != count {
					t.Fatalf("offset=%d count=%d refused", offset, count)
				}
				var body []byte
				whole := 0
				for _, p := range parts {
					body = append(body, p[5:]...)
					if bytes.Contains(p[5:], []byte(name)) {
						whole++
					}
				}
				if whole != 1 || bytes.Contains(parts[0], []byte(name)) || !bytes.Equal(body, hello[5:]) {
					t.Fatalf("offset=%d count=%d corrupt", offset, count)
				}
			}
		}
	}
}
func TestMiragePreservesFollowingRecord(t *testing.T) {
	hello := paddedMirageHello("example.test", 16)
	trailer := []byte{20, 3, 3, 0, 1, 1}
	input := append(append([]byte(nil), hello...), trailer...)
	parts, n, ok := mirageParts(input, 5, 3)
	if !ok || n != 3 || len(parts) != 4 || !bytes.Equal(parts[3], trailer) {
		t.Fatal("following record consumed")
	}
	var body []byte
	for _, p := range parts[:n] {
		body = append(body, p[5:]...)
	}
	if !bytes.Equal(body, hello[5:]) {
		t.Fatal("corrupted hello")
	}
}

type shortMirageConn struct {
	net.Conn
	calls int
}

func (c *shortMirageConn) Write(b []byte) (int, error) { c.calls++; return len(b) - 1, nil }
func TestMirageShortWritePoisonsConnection(t *testing.T) {
	raw := &shortMirageConn{}
	c := NewMirageConn(raw, 5, 2, false)
	hello := paddedMirageHello("example.test", 16)
	n, err := c.Write(hello)
	if !errors.Is(err, io.ErrShortWrite) || n >= len(hello) {
		t.Fatalf("false success %d %v", n, err)
	}
	if _, err = c.Write(hello); !errors.Is(err, io.ErrShortWrite) || raw.calls != 1 {
		t.Fatal("retried corrupt stream")
	}
}
func TestMirageEmptyWriteDoesNotDisableFragmentation(t *testing.T) {
	raw := &captureConn{}
	c := NewMirageConn(raw, 5, 2, false)
	if _, err := c.Write(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(makeClientHello("example.test")); err != nil {
		t.Fatal(err)
	}
	if raw.writes != 2 {
		t.Fatalf("zero write bypassed fragmentation: %d", raw.writes)
	}
}
func TestMirageConcurrentWritesDoNotInterleaveRecords(t *testing.T) {
	raw := &captureConn{}
	c := NewMirageConn(raw, 5, 2, false)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = c.Write(makeClientHello("example.test")) }()
	}
	wg.Wait()
	if raw.writes != 21 {
		t.Fatalf("writes=%d", raw.writes)
	}
}
func TestMirageWriteCountsAndCoalescing(t *testing.T) {
	hello := paddedMirageHello("example.test", 16)
	for _, coalesce := range []bool{false, true} {
		raw := &captureConn{}
		c := NewMirageConn(raw, 5, 4, coalesce)
		n, err := c.Write(hello)
		want := 4
		if coalesce {
			want = 1
		}
		if err != nil || n != len(hello) || raw.writes != want {
			t.Fatalf("coalesce=%v n=%d err=%v writes=%d", coalesce, n, err, raw.writes)
		}
	}
}
func TestMirageRejectsInconsistentNestedLengths(t *testing.T) {
	hello := paddedMirageHello("example.test", 16)
	for _, at := range []int{3, 6, 50, 54, 56, 59} {
		bad := append([]byte(nil), hello...)
		bad[at] = 255
		if _, _, ok := mirageParts(bad, 5, 2); ok {
			t.Fatalf("accepted invalid length at %d", at)
		}
	}
}
func TestMirageAppliedShapeReportsActualNotRequested(t *testing.T) {
	c := NewMirageConn(&captureConn{}, 1024, 8, false)
	if _, _, _, ok := c.AppliedShape(); ok {
		t.Fatal("applied before write")
	}
	// No post-SNI bytes: cannot honestly claim eight records.
	if _, err := c.Write(makeClientHello("example.test")); err != nil {
		t.Fatal(err)
	}
	offset, count, _, ok := c.AppliedShape()
	if !ok || offset != 5 || count != 2 {
		t.Fatalf("reported %d/%d/%v", offset, count, ok)
	}
	plain := NewMirageConn(&captureConn{}, 5, 2, false)
	_, _ = plain.Write([]byte("not TLS"))
	if _, _, _, ok := plain.AppliedShape(); ok {
		t.Fatal("credited unfragmented data")
	}
}

func FuzzMirageWire(f *testing.F) {
	f.Add(paddedMirageHello("example.test", 20), 5, 3)
	f.Add([]byte{22, 3, 1}, 1024, 8)
	f.Fuzz(func(t *testing.T, b []byte, offset, count int) {
		parts, n, ok := mirageParts(b, offset, count)
		if !ok {
			return
		}
		if n < 2 || n > 8 {
			t.Fatal("unbounded fragments")
		}
		var body []byte
		for _, p := range parts[:n] {
			if len(p) <= 5 || int(binary.BigEndian.Uint16(p[3:5])) != len(p)-5 {
				t.Fatal("invalid record")
			}
			body = append(body, p[5:]...)
		}
		end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if !bytes.Equal(body, b[5:end]) {
			t.Fatal("changed hello")
		}
		if !bytes.Equal(bytes.Join(parts[n:], nil), b[end:]) {
			t.Fatal("changed trailing bytes")
		}
	})
}
