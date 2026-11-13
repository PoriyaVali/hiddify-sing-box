package tf

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func defaultShape() MirageShape { return mirageAutoCandidates[0] }

func indexOf(t *testing.T, book *MirageBook, shape MirageShape) int {
	t.Helper()
	for i, candidate := range book.candidates {
		if candidate == shape {
			return i
		}
	}
	t.Fatalf("%v is not a candidate", shape)
	return -1
}

func TestMirageBookRotatesAndRemembers(t *testing.T) {
	t.Parallel()
	book := newMirageBook(defaultShape())
	require.Len(t, book.candidates, len(mirageAutoCandidates))
	require.Equal(t, MirageShape{Off: true}, book.candidates[len(book.candidates)-1], "untouched is the last resort")

	// An unproven shape goes at its first failure.
	require.Equal(t, 0, book.pick("a"))
	book.report("a", 0, false)
	require.Equal(t, book.candidates[1], book.Current("a"))

	// A proven one needs two in a row; a success in between resets the count.
	require.Equal(t, 1, book.pick("a"))
	book.report("a", 1, true)
	book.report("a", 1, false)
	require.Equal(t, book.candidates[1], book.Current("a"))
	book.report("a", 1, true)
	book.report("a", 1, false)
	require.Equal(t, book.candidates[1], book.Current("a"))
	book.report("a", 1, false)
	require.Equal(t, book.candidates[2], book.Current("a"))

	// A server seen afterwards starts where the last success was.
	require.Equal(t, 1, book.pick("b"))
}

func TestMirageBookIgnoresVerdictsAboutAShapeItLeft(t *testing.T) {
	t.Parallel()
	book := newMirageBook(defaultShape())
	// Three connections opened together, all with shape 0, all fail.
	for range 3 {
		require.Equal(t, 0, book.pick("a"))
	}
	for range 3 {
		book.report("a", 0, false)
	}
	require.Equal(t, book.candidates[1], book.Current("a"), "one burst must move the server one step, not three")
}

func TestMirageBookNeverRunsOut(t *testing.T) {
	t.Parallel()
	book := newMirageBook(defaultShape())
	seen := map[MirageShape]bool{}
	for i := 0; i < 2*len(book.candidates); i++ {
		index := book.pick("a")
		seen[book.candidates[index]] = true
		book.report("a", index, false)
	}
	require.Len(t, seen, len(book.candidates), "every candidate, untouched included, gets its turn")
	require.Equal(t, 0, book.pick("a"), "after the last candidate the cycle starts again")
}

func TestMirageBookPutsAConfiguredShapeFirst(t *testing.T) {
	t.Parallel()
	custom := newMirageBook(MirageShape{Offset: 64, Records: 2})
	require.Equal(t, MirageShape{Offset: 64, Records: 2}, custom.candidates[0])
	require.Len(t, custom.candidates, len(mirageAutoCandidates)+1)

	known := newMirageBook(MirageShape{Offset: 5, Records: 3})
	require.Equal(t, MirageShape{Offset: 5, Records: 3}, known.candidates[0])
	require.Len(t, known.candidates, len(mirageAutoCandidates), "a candidate is moved, not duplicated")

	require.Same(t, MirageAutoBook(5, 2, false), MirageAutoBook(0, 0, false), "zero values mean the default shape")
}

func TestMirageBookStaysBounded(t *testing.T) {
	t.Parallel()
	book := newMirageBook(defaultShape())
	for i := range mirageBookMaxEntries + 10 {
		book.pick(string(rune(i)))
	}
	require.LessOrEqual(t, len(book.entries), mirageBookMaxEntries)
}

// censor is a TCP proxy in front of a real TLS server. It reads the whole
// first ClientHello, keeping its TLS record boundaries, and either forwards
// the connection, resets it, or goes silent - the three things the carriers
// measured in 2026 do.
type censorVerdict int

const (
	censorPass censorVerdict = iota
	censorReset
	censorSilence
)

type censor struct {
	listener net.Listener
	backend  string
	rule     func(firstRecord []byte, records int) censorVerdict
	wg       sync.WaitGroup
	mu       sync.Mutex
	held     []net.Conn
}

func newCensor(t *testing.T, backend string, rule func([]byte, int) censorVerdict) *censor {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	c := &censor{listener: listener, backend: backend, rule: rule}
	c.wg.Add(1)
	go c.serve()
	t.Cleanup(func() {
		listener.Close()
		c.mu.Lock()
		for _, conn := range c.held {
			conn.Close()
		}
		c.mu.Unlock()
		c.wg.Wait()
	})
	return c
}

func (c *censor) serve() {
	defer c.wg.Done()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			return
		}
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handle(conn)
		}()
	}
}

func (c *censor) handle(conn net.Conn) {
	var stream []byte
	var first []byte
	records := 0
	want := -1
	have := 0
	buf := make([]byte, 4096)
	for want < 0 || have < want {
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return
		}
		stream = append(stream, buf[:n]...)
		// Re-walk the records collected so far. The handshake header can
		// itself be split across records (a first record of one byte).
		records, have, first = 0, 0, nil
		var handshake []byte
		for rest := stream; len(rest) >= 5; {
			size := int(binary.BigEndian.Uint16(rest[3:5]))
			if len(rest) < 5+size {
				break
			}
			payload := rest[5 : 5+size]
			if records == 0 {
				first = payload
			}
			handshake = append(handshake, payload...)
			records++
			have += size
			rest = rest[5+size:]
		}
		if len(handshake) >= 4 {
			want = 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
		}
	}
	switch c.rule(first, records) {
	case censorReset:
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetLinger(0)
		}
		conn.Close()
		return
	case censorSilence:
		c.mu.Lock()
		c.held = append(c.held, conn)
		c.mu.Unlock()
		return
	}
	backend, err := net.Dial("tcp", c.backend)
	if err != nil {
		conn.Close()
		return
	}
	backend.Write(stream)
	go func() {
		io.Copy(backend, conn)
		backend.Close()
	}()
	io.Copy(conn, backend)
	conn.Close()
}

func tlsBackend(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// handshakes runs n TLS handshakes in a row through the censor, as a user's
// connections would, and reports which ones completed.
func handshakes(t *testing.T, book *MirageBook, address string, n int, timeout time.Duration) []bool {
	t.Helper()
	results := make([]bool, n)
	for i := range n {
		raw, err := net.Dial("tcp", address)
		require.NoError(t, err)
		conn := NewAdaptiveMirageConn(raw, book, "www.example.com")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		client := tls.Client(conn, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
		results[i] = client.HandshakeContext(ctx) == nil
		cancel()
		client.Close()
	}
	return results
}

func testBook(silence time.Duration) *MirageBook {
	book := newMirageBook(defaultShape())
	book.silence = silence
	return book
}

func TestAdaptiveMirageKeepsAWorkingShape(t *testing.T) {
	t.Parallel()
	address := newCensor(t, tlsBackend(t), func([]byte, int) censorVerdict { return censorPass }).listener.Addr().String()
	book := testBook(time.Second)
	require.Equal(t, []bool{true, true, true}, handshakes(t, book, address, 3, 3*time.Second))
	require.Equal(t, defaultShape(), book.Current("www.example.com|"+address))
}

// Irancell-style: the censor resets any hello whose first record shows the
// name. The untouched hello is the only casualty, and it is left in one step.
func TestAdaptiveMirageLeavesAResetShape(t *testing.T) {
	t.Parallel()
	address := newCensor(t, tlsBackend(t), func(first []byte, _ int) censorVerdict {
		if bytes.Contains(first, []byte("www.example.com")) {
			return censorReset
		}
		return censorPass
	}).listener.Addr().String()
	book := testBook(time.Second)
	key := "www.example.com|" + address
	// Walk the server to the untouched hello, the one this censor resets.
	off := indexOf(t, book, MirageShape{Off: true})
	for book.pick(key) != off {
		book.report(key, book.pick(key), false)
	}
	require.Equal(t, []bool{false, true, true}, handshakes(t, book, address, 3, 3*time.Second))
	require.Equal(t, defaultShape(), book.Current(key), "after the untouched hello the cycle wraps to the first shape")
}

// A censor that has learned the default shape (first record of exactly five
// bytes) costs one connection.
func TestAdaptiveMirageLeavesALearnedShape(t *testing.T) {
	t.Parallel()
	address := newCensor(t, tlsBackend(t), func(first []byte, _ int) censorVerdict {
		if len(first) == 5 {
			return censorReset
		}
		return censorPass
	}).listener.Addr().String()
	book := testBook(time.Second)
	require.Equal(t, []bool{false, true, true, true}, handshakes(t, book, address, 4, 3*time.Second))
	require.Equal(t, MirageShape{Offset: 1, Records: 2}, book.Current("www.example.com|"+address))
}

// MCI-style silence against every fragmented form: each costs one connection,
// and the untouched hello - the last resort - still gets the user through.
func TestAdaptiveMirageOutlastsSilence(t *testing.T) {
	t.Parallel()
	address := newCensor(t, tlsBackend(t), func(_ []byte, records int) censorVerdict {
		if records > 1 {
			return censorSilence
		}
		return censorPass
	}).listener.Addr().String()
	silence := 200 * time.Millisecond
	book := testBook(silence)
	results := handshakes(t, book, address, len(book.candidates)+1, 3*silence)
	fragmented := len(book.candidates) - 1
	for i := range fragmented {
		require.False(t, results[i], "attempt %d", i)
	}
	require.True(t, results[fragmented], "the untouched hello must get through")
	require.True(t, results[fragmented+1], "and keep getting through")
	require.Equal(t, MirageShape{Off: true}, book.Current("www.example.com|"+address))
}

// A caller that gives up before the silence limit has learned nothing about
// the shape, so the shape must stay.
func TestAdaptiveMirageIgnoresCallersThatGiveUpEarly(t *testing.T) {
	t.Parallel()
	address := newCensor(t, tlsBackend(t), func([]byte, int) censorVerdict { return censorSilence }).listener.Addr().String()
	book := testBook(2 * time.Second)
	require.Equal(t, []bool{false, false}, handshakes(t, book, address, 2, 100*time.Millisecond))
	require.Equal(t, defaultShape(), book.Current("www.example.com|"+address))
}

// wireConn is a captureConn that can also be asked for its address and closed.
type wireConn struct{ captureConn }

func (c *wireConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443} }
func (c *wireConn) Close() error         { return nil }

func TestAdaptiveMirageReportsTheShapeItSent(t *testing.T) {
	t.Parallel()
	hello := makeClientHello("www.instagram.com")
	cap := &wireConn{}
	conn := NewAdaptiveMirageConn(cap, testBook(time.Second), "www.instagram.com")
	n, err := conn.Write(hello)
	require.NoError(t, err)
	require.Equal(t, len(hello), n)
	shape, ok := conn.AppliedShape()
	require.True(t, ok)
	require.Equal(t, defaultShape(), shape)
	require.Equal(t, 2, cap.writes, "the default shape is two records in two writes")
	conn.Close()

	// Non-TLS traffic is passed through and teaches nothing.
	cap = &wireConn{}
	conn = NewAdaptiveMirageConn(cap, testBook(time.Second), "x")
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)
	_, ok = conn.AppliedShape()
	require.False(t, ok)
	require.True(t, conn.ReaderReplaceable())
}
