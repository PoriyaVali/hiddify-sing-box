package session

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestSynTimeoutFollowsAcknowledgements(t *testing.T) {
	var none *synRTT
	if got := none.timeout(); got != synTimeoutMin {
		t.Fatalf("no estimate: %v, want %v", got, synTimeoutMin)
	}
	var r synRTT
	if got := r.timeout(); got != synTimeoutMin {
		t.Fatalf("no samples: %v, want %v", got, synTimeoutMin)
	}
	r.observe(200 * time.Millisecond)
	if got := r.timeout(); got != synTimeoutMin {
		t.Fatalf("a fast link keeps the floor: %v", got)
	}
	r.observe(2500 * time.Millisecond)
	if got := r.timeout(); got != 6*time.Second {
		t.Fatalf("a slow acknowledgement counts at once: %v, want 6s", got)
	}
	r.observe(500 * time.Millisecond)
	if got := r.timeout(); got != 5*time.Second {
		t.Fatalf("a fast one pulls a quarter of the gap: %v, want 5s", got)
	}
	r.observe(20 * time.Second)
	if got := r.timeout(); got != synTimeoutMax {
		t.Fatalf("capped: %v, want %v", got, synTimeoutMax)
	}
}

// sessionPair is a client session wired to a server session over a pipe. The
// server acknowledges each new stream after ackDelay(sid); a negative delay
// never acknowledges.
func sessionPair(t *testing.T, ackDelay func(sid uint32) time.Duration) (*Session, *synRTT) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	pad := defaultPadding()
	server := NewServerSession(s, func(stream *Stream) {
		// Read the stream as a real server does: an unread stream's pipe
		// stops the server's receive loop, and with it the connection.
		go io.Copy(io.Discard, stream)
		d := ackDelay(stream.id)
		if d < 0 {
			return
		}
		time.Sleep(d)
		_ = stream.HandshakeSuccess()
	}, pad, logger.NOP())
	go server.Run()
	t.Cleanup(func() { server.Close() })

	est := &synRTT{}
	client := NewClientSession(c, pad, logger.NOP())
	client.synRTT = est
	client.Run()
	t.Cleanup(func() { client.Close() })
	return client, est
}

// openAndWait opens a stream, flushes it with one byte, and waits until the
// pool has seen that stream acknowledged.
func openAndWait(t *testing.T, client *Session, est *synRTT) *Stream {
	t.Helper()
	before := est.est.Load()
	st, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for est.est.Load() == before && client.synSent.Load() != nil {
		if time.Now().After(deadline) {
			t.Fatal("stream never acknowledged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return st
}

// 🔴 A reused session must not be closed for an acknowledgement that is slow
// but no slower than this link's acknowledgements have been. With a fixed
// three seconds, a live session on a link whose SYNACKs take 2.5 s was closed
// - and the user's request with it - whenever one took four.
func TestReusedSessionSurvivesSlowAcknowledgement(t *testing.T) {
	if testing.Short() {
		t.Skip("waits on deliberately slow acknowledgements")
	}
	client, est := sessionPair(t, func(sid uint32) time.Duration {
		if sid == 1 {
			return 2500 * time.Millisecond
		}
		return 4 * time.Second
	})
	first := openAndWait(t, client, est)
	first.Close()

	second, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4500 * time.Millisecond)
	if client.IsClosed() {
		t.Fatal("a live session was closed while its slow acknowledgement was on the way")
	}
}

// An acknowledgement is timed against its own stream's SYN. A late SYNACK for
// one stream, arriving after the session sent the next stream's SYN, was
// timed against that newer SYN: a sample far too short, while the newer
// stream's own acknowledgement found nothing left to time. The estimate fell,
// and with it the allowance that keeps a live reused session from being
// closed (Codex review of hiddify-sing-box#2).
func TestAcknowledgementIsTimedAgainstItsOwnStream(t *testing.T) {
	client, est := sessionPair(t, func(sid uint32) time.Duration {
		if sid == 1 {
			return 600 * time.Millisecond
		}
		return 2 * time.Second
	})
	first, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	// Sent while the first stream's acknowledgement is still on its way.
	second, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Duration(est.est.Load()) < 1500*time.Millisecond {
		if time.Now().After(deadline) {
			t.Fatalf("estimate %v; the second stream's 2 s acknowledgement was never timed", time.Duration(est.est.Load()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A session that never acknowledges a new stream is still found dead quickly
// on a fast link.
func TestReusedSessionClosedWhenNeverAcknowledged(t *testing.T) {
	client, est := sessionPair(t, func(sid uint32) time.Duration {
		if sid == 1 {
			return 50 * time.Millisecond
		}
		return -1
	})
	first := openAndWait(t, client, est)
	first.Close()

	start := time.Now()
	second, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = second.Write([]byte{0})
	for !client.IsClosed() {
		if time.Since(start) > synTimeoutMin+2*time.Second {
			t.Fatal("a session that never acknowledged was kept")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if took := time.Since(start); took < synTimeoutMin-100*time.Millisecond {
		t.Fatalf("closed after %v, before the allowance", took)
	}
}
