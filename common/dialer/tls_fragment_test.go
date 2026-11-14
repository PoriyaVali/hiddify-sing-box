package dialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordingConn keeps every Write separately, which is what reaches the wire
// as separate segments with TCP_NODELAY.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingConn) Close() error             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (c *recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

// clientHello returns the first write of a real crypto/tls handshake.
func clientHello(t *testing.T) []byte {
	t.Helper()
	conn := &recordingConn{}
	_ = tls.Client(conn, &tls.Config{ServerName: "www.example.com"}).Handshake()
	if len(conn.writes) == 0 {
		t.Fatal("no ClientHello written")
	}
	return conn.writes[0]
}

type tlsRecord struct {
	contentType byte
	version     [2]byte
	payload     []byte
}

func parseRecords(t *testing.T, stream []byte) []tlsRecord {
	t.Helper()
	var records []tlsRecord
	for len(stream) > 0 {
		if len(stream) < 5 {
			t.Fatalf("truncated record header: %x", stream)
		}
		n := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+n {
			t.Fatalf("truncated record: want %d bytes, have %d", n, len(stream)-5)
		}
		records = append(records, tlsRecord{stream[0], [2]byte{stream[1], stream[2]}, stream[5 : 5+n]})
		stream = stream[5+n:]
	}
	return records
}

func TestParseTLSFragmentRange(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value        string
		lower, upper int
		want         tlsFragmentRange
	}{
		{"10-30", 1, tlsMaxRecordPayload, tlsFragmentRange{10, 30}},
		{" 10 - 30 ", 1, tlsMaxRecordPayload, tlsFragmentRange{10, 30}},
		{"5", 1, tlsMaxRecordPayload, tlsFragmentRange{5, 5}},
		{"30-10", 1, tlsMaxRecordPayload, tlsFragmentRange{10, 30}},
		{"0-0", 1, tlsMaxRecordPayload, tlsFragmentRange{1, 1}},
		{"", 1, tlsMaxRecordPayload, defaultTLSFragmentSize},
		{"ten", 1, tlsMaxRecordPayload, defaultTLSFragmentSize},
		{"10-x", 1, tlsMaxRecordPayload, defaultTLSFragmentSize},
		{"0", 0, tlsFragmentMaxSleepMilli, tlsFragmentRange{0, 0}},
		{"50-5000", 0, tlsFragmentMaxSleepMilli, tlsFragmentRange{50, tlsFragmentMaxSleepMilli}},
	} {
		fallback := defaultTLSFragmentSize
		if got := parseTLSFragmentRange(tc.value, fallback, tc.lower, tc.upper); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.value, got, tc.want)
		}
	}
	if newTLSFragmentConfig(option.TLSFragmentOptions{Size: "10-30"}) != nil {
		t.Error("a disabled option must not fragment")
	}
}

func TestTLSFragmentSplitsClientHelloIntoSeparateWrites(t *testing.T) {
	t.Parallel()
	hello := clientHello(t)
	original := parseRecords(t, hello)
	if len(original) != 1 {
		t.Fatalf("ClientHello should be one record, got %d", len(original))
	}
	wire := &recordingConn{}
	config := newTLSFragmentConfig(option.TLSFragmentOptions{Enabled: true, Size: "10-30", Sleep: "0-1"})
	conn := config.wrap(wire)

	n, err := conn.Write(hello)
	if err != nil || n != len(hello) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(hello))
	}
	if len(wire.writes) < len(original[0].payload)/30 {
		t.Fatalf("%d writes for a %d-byte hello", len(wire.writes), len(original[0].payload))
	}
	var payload []byte
	for i, w := range wire.writes {
		records := parseRecords(t, w)
		if len(records) != 1 {
			t.Fatalf("write %d carries %d records, want one record per write", i, len(records))
		}
		r := records[0]
		if r.contentType != 0x16 || r.version != original[0].version {
			t.Fatalf("write %d: header %x %x changed", i, r.contentType, r.version)
		}
		if len(r.payload) > 30 || len(r.payload) < 10 && i != len(wire.writes)-1 {
			t.Fatalf("write %d: payload %d outside 10-30", i, len(r.payload))
		}
		payload = append(payload, r.payload...)
	}
	if !bytes.Equal(payload, original[0].payload) {
		t.Fatal("the records do not reassemble into the original handshake")
	}

	// Only the first write is touched.
	before := len(wire.writes)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if len(wire.writes) != before+1 || !bytes.Equal(wire.writes[before], hello) {
		t.Fatal("a later write was fragmented")
	}
}

func TestTLSFragmentZeroSleepKeepsOneWrite(t *testing.T) {
	t.Parallel()
	hello := clientHello(t)
	wire := &recordingConn{}
	conn := newTLSFragmentConfig(option.TLSFragmentOptions{Enabled: true, Size: "10-30", Sleep: "0"}).wrap(wire)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if len(wire.writes) != 1 {
		t.Fatalf("%d writes, want the records coalesced in one", len(wire.writes))
	}
	records := parseRecords(t, wire.writes[0])
	if len(records) < 2 {
		t.Fatalf("%d records, want the hello split", len(records))
	}
	var payload []byte
	for _, r := range records {
		payload = append(payload, r.payload...)
	}
	if !bytes.Equal(payload, parseRecords(t, hello)[0].payload) {
		t.Fatal("the records do not reassemble into the original handshake")
	}
}

func TestTLSFragmentKeepsTrailingBytesAndIgnoresOtherTraffic(t *testing.T) {
	t.Parallel()
	hello := clientHello(t)
	trailer := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	wire := &recordingConn{}
	conn := newTLSFragmentConfig(option.TLSFragmentOptions{Enabled: true, Size: "100", Sleep: "1"}).wrap(wire)
	n, err := conn.Write(append(append([]byte(nil), hello...), trailer...))
	if err != nil || n != len(hello)+len(trailer) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if last := wire.writes[len(wire.writes)-1]; !bytes.Equal(last, trailer) {
		t.Fatalf("trailing bytes %x, want %x", last, trailer)
	}

	for _, first := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, // ServerHello type
		hello[:len(hello)-1], // incomplete record
	} {
		wire := &recordingConn{}
		conn := newTLSFragmentConfig(option.TLSFragmentOptions{Enabled: true, Size: "1-2", Sleep: "0"}).wrap(wire)
		if _, err := conn.Write(first); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		if len(wire.writes) != 2 || !bytes.Equal(wire.writes[0], first) || !bytes.Equal(wire.writes[1], hello) {
			t.Fatalf("first write %q: traffic was altered", first[:min(len(first), 8)])
		}
	}
}

// The dialer itself: before this option was read, the server received the
// ClientHello as the single record the TLS stack wrote.
func TestDefaultDialerAppliesTLSFragment(t *testing.T) {
	t.Parallel()
	hello := clientHello(t)
	for _, tc := range []struct {
		name    string
		options option.TLSFragmentOptions
		records func(int) bool
	}{
		{"disabled", option.TLSFragmentOptions{}, func(n int) bool { return n == 1 }},
		{"enabled", option.TLSFragmentOptions{Enabled: true, Size: "10-30", Sleep: "1-2"}, func(n int) bool { return n > 5 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					received <- nil
					return
				}
				defer conn.Close()
				data, _ := io.ReadAll(conn)
				received <- data
			}()

			dialer, err := NewDefault(context.Background(), option.DialerOptions{TLSFragment: tc.options})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.DialContext(context.Background(), "tcp", M.SocksaddrFromNet(listener.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(hello); err != nil {
				t.Fatal(err)
			}
			conn.Close()
			data := <-received
			records := parseRecords(t, data)
			if !tc.records(len(records)) {
				t.Fatalf("server received %d records", len(records))
			}
			var payload []byte
			for _, r := range records {
				payload = append(payload, r.payload...)
			}
			if !bytes.Equal(payload, parseRecords(t, hello)[0].payload) {
				t.Fatal("the server cannot reassemble the handshake")
			}
		})
	}
}

type earlyConn struct{ recordingConn }

func (c *earlyConn) NeedHandshake() bool { return true }

// The wrapper must not hide what the router needs from the connection under
// it: half-close, and a TCP Fast Open connection's early write.
func TestTLSFragmentKeepsTheConnectionsAbilities(t *testing.T) {
	t.Parallel()
	config := newTLSFragmentConfig(option.TLSFragmentOptions{Enabled: true, Size: "10-30", Sleep: "0"})

	t.Run("half-close", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			request, _ := io.ReadAll(conn) // until the client's half-close
			conn.Write(append([]byte("echo:"), request...))
		}()
		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn := config.wrap(raw)
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		closer, ok := conn.(N.WriteCloser)
		if !ok {
			t.Fatal("the wrapper hides CloseWrite")
		}
		if err := closer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		answer, err := io.ReadAll(conn)
		if err != nil || string(answer) != "echo:ping" {
			t.Fatalf("after a half-close got %q, %v", answer, err)
		}
	})

	t.Run("fast open", func(t *testing.T) {
		t.Parallel()
		wire := &earlyConn{}
		conn := config.wrap(wire)
		if !N.NeedHandshakeForWrite(conn) {
			t.Fatal("the wrapper hides the early-write request")
		}
		if _, err := conn.Write(nil); err != nil {
			t.Fatal(err)
		}
		if len(wire.writes) != 1 || len(wire.writes[0]) != 0 {
			t.Fatalf("the empty write did not reach the connection: %d writes", len(wire.writes))
		}
		if _, err := conn.Write(clientHello(t)); err != nil {
			t.Fatal(err)
		}
		if records := parseRecords(t, wire.writes[1]); len(records) < 2 {
			t.Fatal("the ClientHello after an empty write was not fragmented")
		}
	})
}
