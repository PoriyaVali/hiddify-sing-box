package session

import (
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

func defaultPadding() *atomic.TypedValue[*padding.PaddingFactory] {
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	return &pad
}

// pacedLink is the client's end of a connection whose peer reads at most
// 4 KiB every interval: a throttled uplink, drained at a steady rate. A write
// on it returns once the peer has read all of it.
//
// It is an in-memory pipe, not loopback TCP. With socket buffers small enough
// to make writes wait, the kernel keeps closing the receive window and
// recovers through zero-window probes with growing backoff - stalls of
// seconds, more than these timings can tell apart from a dead peer.
func pacedLink(t *testing.T, interval time.Duration) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			time.Sleep(interval)
		}
	}()
	return local
}

// stalledLink is the client's end of a connection whose peer never reads: a
// path that died with data in flight.
func stalledLink(t *testing.T) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	return local
}

// 🔴 A FIN queued behind an upload must neither cut that upload short nor
// close the session.
//
// writeControlFrame set a five-second write deadline on the whole connection
// before waiting for the write lock. An upload still draining over a slow
// uplink inherited that deadline and failed, and the FIN of a stream being
// closed, finding its deadline already spent once it got the lock, closed the
// session instead of returning it to the pool - the next request then paid
// for a new TLS handshake over the same weak link.
func TestControlFrameBehindSlowUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("drains an upload over a deliberately slow link")
	}
	// 8 KiB/s, a heavily throttled mobile uplink.
	s := NewClientSession(pacedLink(t, 500*time.Millisecond), defaultPadding(), logger.NOP())
	defer s.Close()

	// One full data frame: about eight seconds at this rate.
	dataErr := make(chan error, 1)
	go func() {
		_, err := s.writeDataFrame(1, make([]byte, 64000))
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond) // the upload holds the line
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeControlFrame(newFrame(cmdFIN, 2))
		ctrlErr <- err
	}()

	if err := <-dataErr; err != nil {
		t.Fatalf("an upload was cut short by a control frame's deadline: %v", err)
	}
	if err := <-ctrlErr; err != nil {
		t.Fatalf("the FIN failed behind a slow upload: %v", err)
	}
	if s.IsClosed() {
		t.Fatal("the session was closed over a slow link")
	}
}

// 🔴 A control frame behind a write that can never finish must not wait for
// it forever: the session is closed once nothing has left for the timeout.
func TestControlFrameBehindStalledWriteIsBounded(t *testing.T) {
	s := NewClientSession(stalledLink(t), defaultPadding(), logger.NOP())
	defer s.Close()

	dataErr := make(chan error, 1)
	go func() {
		_, err := s.writeDataFrame(1, make([]byte, 1<<20))
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond) // the writer is stuck holding the line
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeConnWithin([]byte{cmdFIN, 0, 0, 0, 1, 0, 0}, 500*time.Millisecond)
		ctrlErr <- err
	}()

	select {
	case err := <-ctrlErr:
		if err == nil {
			t.Fatal("a control frame reported success on a connection that stopped draining")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a control frame behind a stalled write waited without bound")
	}
	select {
	case err := <-dataErr:
		if err == nil {
			t.Fatal("the stalled write reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled write was never released")
	}
	if !s.IsClosed() {
		t.Fatal("the session was left open on a connection that cannot drain")
	}
}

// 🔴 A write that takes longer than a control frame's patience, but keeps
// moving, is a slow link, not a dead one: the session must survive it.
func TestControlFrameWaitsOutASlowButMovingWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("drains a large write over a deliberately slow link")
	}
	// 16 KiB/s: 96 KiB takes six seconds, twice the patience below, and each
	// 16 KiB chunk one.
	s := NewClientSession(pacedLink(t, 250*time.Millisecond), defaultPadding(), logger.NOP())
	defer s.Close()

	dataErr := make(chan error, 1)
	go func() {
		_, err := s.writeDataFrame(1, make([]byte, 96<<10))
		dataErr <- err
	}()
	time.Sleep(300 * time.Millisecond)
	ctrlErr := make(chan error, 1)
	go func() {
		_, err := s.writeConnWithin([]byte{cmdFIN, 0, 0, 0, 2, 0, 0}, 3*time.Second)
		ctrlErr <- err
	}()

	if err := <-dataErr; err != nil {
		t.Fatalf("a slow but moving write was cut: %v", err)
	}
	if err := <-ctrlErr; err != nil {
		t.Fatalf("the control frame failed behind a slow but moving write: %v", err)
	}
	if s.IsClosed() {
		t.Fatal("the session was closed although its write kept moving")
	}
}

// 🔴 Padded records count as progress too, including one larger than a chunk:
// the server's padding scheme sizes them, and on a weak link a packet of
// several records outlasts a control frame's patience.
func TestControlFrameWaitsOutSlowPaddedRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("drains padded records over a deliberately slow link")
	}
	for _, scheme := range []string{
		"stop=2\n1=12000-12000,12000-12000,12000-12000,12000-12000,12000-12000,12000-12000",
		"stop=2\n1=60000-60000",
	} {
		var pad atomic.TypedValue[*padding.PaddingFactory]
		if !padding.UpdatePaddingScheme([]byte(scheme), &pad) {
			t.Fatal("padding scheme rejected")
		}
		// 16 KiB/s: either packet takes over twice the patience below.
		s := NewClientSession(pacedLink(t, 250*time.Millisecond), &pad, logger.NOP())

		dataErr := make(chan error, 1)
		go func() {
			_, err := s.writeConnWithin(make([]byte, 100), 0)
			dataErr <- err
		}()
		time.Sleep(300 * time.Millisecond)
		ctrlErr := make(chan error, 1)
		go func() {
			_, err := s.writeConnWithin([]byte{cmdFIN, 0, 0, 0, 2, 0, 0}, 2*time.Second)
			ctrlErr <- err
		}()

		if err := <-dataErr; err != nil {
			t.Fatalf("%q: a slow but moving padded write was cut: %v", scheme, err)
		}
		if err := <-ctrlErr; err != nil {
			t.Fatalf("%q: the control frame failed behind slow padded records: %v", scheme, err)
		}
		if s.IsClosed() {
			t.Fatalf("%q: the session was closed although its padded records kept leaving", scheme)
		}
		s.Close()
	}
}
