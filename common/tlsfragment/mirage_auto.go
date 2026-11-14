package tf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Adaptive Mirage (Doctor Mobile).
//
// A fixed shape is a bet on one carrier's censor. Two carriers measured in the
// same month disagreed (MCI drops the single-write form that Irancell accepts,
// and an August Irancell run found the opposite), and a censor can change its
// rule overnight. Choosing a shape from the app with separate probe
// connections had to pause 90 s between probes, because that censor punishes
// bursts, so it took about ten minutes to settle.
//
// Adaptive Mirage learns from the connections that are being made anyway, so
// it adds no attempts of its own. Each new ClientHello goes out in the shape
// that last worked for that server. The connection watches for the server's
// first reply: bytes back mean the shape got through; a reset, an early close
// or silence means it did not, and the next connection to that server uses the
// next shape:
//
//   - A shape that has worked needs two failures in a row before it is dropped
//     (one stray timeout on a weak network must not move a good shape); a shape
//     that has not worked yet is dropped at its first failure, so a censor that
//     kills every connection in one shape is left behind within seconds.
//   - The shape that last worked anywhere is where servers seen afterwards
//     start, so after a network change one server's discovery spreads.
//   - It never runs out: after every fragmented form, the last candidate is the
//     untouched ClientHello - a network that drops every fragment but lets the
//     name through still connects - and then the cycle starts again.
//
// Nothing here can make a dead server answer, and a server that refuses every
// shape will cycle through them; what it guarantees is that no single shape a
// carrier has learned to drop can strand the user.

// MirageShape is one form of the first ClientHello. Off sends it untouched.
type MirageShape struct {
	Offset   int
	Records  int
	Coalesce bool
	Off      bool
}

func (s MirageShape) String() string {
	if s.Off {
		return "off"
	}
	writes := "separate"
	if s.Coalesce {
		writes = "coalesced"
	}
	return fmt.Sprintf("offset=%d records=%d %s", s.Offset, s.Records, writes)
}

func (s MirageShape) normalized() MirageShape {
	if s.Off {
		return MirageShape{Off: true}
	}
	if s.Offset <= 0 {
		s.Offset = mirageDefaultOffset
	}
	if s.Records < 2 {
		s.Records = 2
	}
	if s.Records > 8 {
		s.Records = 8
	}
	return s
}

// mirageAutoCandidates is the app's MirageShape.candidates in the same order,
// then the untouched hello as the last resort.
var mirageAutoCandidates = []MirageShape{
	{Offset: 5, Records: 2},
	{Offset: 1, Records: 2},
	{Offset: 2, Records: 2},
	{Offset: 5, Records: 3},
	{Offset: 5, Records: 2, Coalesce: true},
	{Offset: 5, Records: 3, Coalesce: true},
	{Off: true},
}

const (
	// mirageSilence is how long a ClientHello may go unanswered before the
	// shape is counted as dropped. The connection itself keeps waiting; only
	// the next connections change shape. Real ServerHellos arrive within one
	// or two round trips, so five seconds of nothing is a drop, not latency.
	// It is also the line between a caller giving up on its own connection
	// (no verdict) and a drop.
	mirageSilence        = 5 * time.Second
	mirageProvenFailures = 2
	mirageBookMaxEntries = 1024
)

// MirageBook remembers, per server, which candidate is in use.
type MirageBook struct {
	mu         sync.Mutex
	candidates []MirageShape
	entries    map[string]*mirageBookEntry
	hint       int
	silence    time.Duration
	clock      func() time.Time
}

type mirageBookEntry struct {
	index    int
	failures int
	proven   bool
	used     time.Time
}

var mirageBooks sync.Map // MirageShape -> *MirageBook

// MirageAutoBook returns the process-wide book that starts from the configured
// shape. The configured shape is tried first; a shape that is not one of the
// candidates is put in front of them.
func MirageAutoBook(offset, records int, coalesce bool) *MirageBook {
	start := MirageShape{Offset: offset, Records: records, Coalesce: coalesce}.normalized()
	if book, ok := mirageBooks.Load(start); ok {
		return book.(*MirageBook)
	}
	book, _ := mirageBooks.LoadOrStore(start, newMirageBook(start))
	return book.(*MirageBook)
}

func newMirageBook(start MirageShape) *MirageBook {
	candidates := []MirageShape{start}
	for _, shape := range mirageAutoCandidates {
		if shape != start {
			candidates = append(candidates, shape)
		}
	}
	return &MirageBook{
		candidates: candidates,
		entries:    make(map[string]*mirageBookEntry),
		silence:    mirageSilence,
		clock:      time.Now,
	}
}

// Current reports the shape the next connection to key will use.
func (b *MirageBook) Current(key string) MirageShape {
	b.mu.Lock()
	defer b.mu.Unlock()
	if entry := b.entries[key]; entry != nil {
		return b.candidates[entry.index]
	}
	return b.candidates[b.hint]
}

func (b *MirageBook) pick(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.entries[key]
	if entry == nil {
		if len(b.entries) >= mirageBookMaxEntries {
			b.evictOldest()
		}
		entry = &mirageBookEntry{index: b.hint}
		b.entries[key] = entry
	}
	entry.used = b.clock()
	return entry.index
}

func (b *MirageBook) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range b.entries {
		if oldestKey == "" || entry.used.Before(oldest) {
			oldestKey, oldest = key, entry.used
		}
	}
	delete(b.entries, oldestKey)
}

// report records the verdict for a connection that used candidate index. A
// verdict about a shape the server has already moved off is ignored, so a
// burst of failures from connections opened together moves it only once.
func (b *MirageBook) report(key string, index int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.entries[key]
	if entry == nil || entry.index != index {
		return
	}
	if ok {
		entry.failures = 0
		entry.proven = true
		b.hint = index
		return
	}
	entry.failures++
	limit := 1
	if entry.proven {
		limit = mirageProvenFailures
	}
	if entry.failures < limit {
		return
	}
	entry.index = (entry.index + 1) % len(b.candidates)
	entry.failures = 0
	entry.proven = false
}

const (
	mirageIdle int32 = iota
	mirageAwaiting
	mirageSettled
)

// AdaptiveMirageConn sends the first ClientHello in the shape its book picks
// for the server and reports how the server answered.
type AdaptiveMirageConn struct {
	net.Conn
	book  *MirageBook
	key   string
	index int
	shape MirageShape

	writeMu      sync.Mutex
	firstWritten bool
	writeErr     error
	applied      bool

	state   atomic.Int32
	closed  atomic.Bool
	timer   atomic.Pointer[time.Timer]
	helloAt atomic.Int64
}

// NewAdaptiveMirageConn wraps conn. serverName is part of the key because a
// censor decides on the name as much as on the address: two nodes behind one
// address (a CDN, or a local chain such as byedpi) keep separate verdicts.
func NewAdaptiveMirageConn(conn net.Conn, book *MirageBook, serverName string) *AdaptiveMirageConn {
	key := serverName
	if addr := conn.RemoteAddr(); addr != nil {
		key += "|" + addr.String()
	}
	return &AdaptiveMirageConn{Conn: conn, book: book, key: key}
}

func (c *AdaptiveMirageConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true
	if !looksLikeClientHello(b) {
		// Not a hello: nothing to choose and nothing to learn from.
		c.state.Store(mirageSettled)
		return c.Conn.Write(b)
	}
	c.index = c.book.pick(c.key)
	c.shape = c.book.candidates[c.index]
	var (
		n   int
		err error
	)
	if c.shape.Off {
		n, err = c.Conn.Write(b)
		c.applied = err == nil
	} else if parts, fragments, ok := mirageParts(b, c.shape.Offset, c.shape.Records); ok {
		n, err = writeMirage(c.Conn, parts, fragments, c.shape.Coalesce)
		c.applied = err == nil
	} else {
		// A hello this codec cannot cut (no server name, say) says nothing
		// about the shape: send it untouched and keep no verdict.
		c.state.Store(mirageSettled)
		return c.Conn.Write(b)
	}
	c.helloAt.Store(time.Now().UnixNano())
	if err != nil {
		c.writeErr = err
		// A reset between records - the censor answering the first record -
		// shows up here as a failed write.
		if c.state.CompareAndSwap(mirageIdle, mirageAwaiting) {
			c.verdictOnError(err)
		}
		return n, err
	}
	if c.state.CompareAndSwap(mirageIdle, mirageAwaiting) {
		c.timer.Store(time.AfterFunc(c.book.silence, func() { c.settle(false) }))
	}
	return n, nil
}

func (c *AdaptiveMirageConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.state.Load() == mirageAwaiting {
		if n > 0 {
			c.settle(true)
		} else if err != nil {
			c.verdictOnError(err)
		}
	}
	return n, err
}

// verdictOnError decides what a failed read or write before the server's first
// byte says about the shape. A reset or close from the other end is a failure.
// Our own close or deadline is only a failure once the silence limit has
// passed: before that the caller simply gave up, which proves nothing.
// Classifying by who closed rather than by errno keeps this the same on every
// platform.
func (c *AdaptiveMirageConn) verdictOnError(err error) {
	local := c.closed.Load() || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
	if local && c.sinceHello() < c.book.silence {
		c.abandon()
		return
	}
	c.settle(false)
}

func (c *AdaptiveMirageConn) sinceHello() time.Duration {
	return time.Duration(time.Now().UnixNano() - c.helloAt.Load())
}

func (c *AdaptiveMirageConn) settle(ok bool) {
	if !c.state.CompareAndSwap(mirageAwaiting, mirageSettled) {
		return
	}
	if timer := c.timer.Load(); timer != nil {
		timer.Stop()
	}
	c.book.report(c.key, c.index, ok)
}

func (c *AdaptiveMirageConn) abandon() {
	if !c.state.CompareAndSwap(mirageAwaiting, mirageSettled) {
		return
	}
	if timer := c.timer.Load(); timer != nil {
		timer.Stop()
	}
}

func (c *AdaptiveMirageConn) Close() error {
	c.closed.Store(true)
	if c.state.Load() == mirageAwaiting && c.sinceHello() < c.book.silence {
		c.abandon()
	}
	return c.Conn.Close()
}

// AppliedShape reports what this connection really sent.
func (c *AdaptiveMirageConn) AppliedShape() (shape MirageShape, ok bool) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.shape, c.applied
}

func (c *AdaptiveMirageConn) Upstream() any {
	return c.Conn
}

// Readers may only bypass this conn once the server's answer has been seen;
// before that the verdict depends on observing the first read.
func (c *AdaptiveMirageConn) ReaderReplaceable() bool {
	return c.state.Load() == mirageSettled
}

func (c *AdaptiveMirageConn) WriterReplaceable() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.firstWritten && c.writeErr == nil
}

func looksLikeClientHello(b []byte) bool {
	return len(b) > 5 && b[0] == 22 && b[1] == 3 && b[5] == 1
}
