package session

import (
	"context"
	"io"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/logger"
)

// slowDial is a server that takes delay to complete each handshake.
func slowDial(t *testing.T, delay time.Duration) (util.DialOutFunc, *atomic.Int32) {
	var dials atomic.Int32
	return func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c, s := net.Pipe()
		t.Cleanup(func() { c.Close(); s.Close() })
		go io.Copy(io.Discard, s)
		return c, nil
	}, &dials
}

func newTestClient(dial util.DialOutFunc, disableReuse bool) *Client {
	return NewClient(context.Background(), logger.NOP(), dial, defaultPadding(), 0, 0, 0, disableReuse)
}

func idleCount(c *Client) int {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	return c.idleSession.Len()
}

// 🔴 A handshake that outlasts the request that started it must not be thrown
// away - an app that cancels, or a URL test's deadline, over a link where a
// TLS handshake takes seconds. It finishes and waits in the pool for the next
// request, instead of every request starting one that never completes.
func TestSlowHandshakeServesTheNextRequest(t *testing.T) {
	dial, dials := slowDial(t, 300*time.Millisecond)
	c := newTestClient(dial, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := c.CreateStream(ctx)
	cancel()
	if err == nil {
		t.Fatal("a request whose deadline passed during the handshake got a stream")
	}
	deadline := time.Now().Add(3 * time.Second)
	for idleCount(c) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the finished handshake never reached the pool")
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	st, err := c.CreateStream(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Fatalf("the next request waited %v, for a handshake of its own", took)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialled %d times, want the one handshake reused", n)
	}
}

// A request waiting on its own slow handshake takes a session that joins the
// pool meanwhile: an app's retry gets the handshake its first attempt gave up
// on as soon as it lands, not one of its own begun later.
func TestWaitingRequestTakesASessionFromThePool(t *testing.T) {
	dial, dials := slowDial(t, 400*time.Millisecond)
	c := newTestClient(dial, false)
	defer c.Close()

	// The first attempt gives up at 100 ms; its handshake lands at 400 ms.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, _ = c.CreateStream(ctx)
	cancel()

	// The retry, at 150 ms, begins a handshake that would land at 550 ms.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	st, err := c.CreateStream(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if took := time.Since(start); took > 350*time.Millisecond {
		t.Fatalf("the retry waited %v, for a handshake of its own", took)
	}
	// Its own handshake is not wasted: it joins the pool too.
	deadline := time.Now().Add(2 * time.Second)
	for idleCount(c) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions idle, want both handshakes kept", idleCount(c))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialled %d times, want 2", n)
	}
}

// Without reuse there is no pool: a handshake finished too late is closed.
func TestSlowHandshakeWithoutReuseIsClosed(t *testing.T) {
	dial, _ := slowDial(t, 200*time.Millisecond)
	c := newTestClient(dial, true)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _ = c.CreateStream(ctx)
	cancel()
	time.Sleep(600 * time.Millisecond)
	c.sessionsLock.Lock()
	left := len(c.sessions)
	c.sessionsLock.Unlock()
	if left != 0 || idleCount(c) != 0 {
		t.Fatalf("a session finished after its request was kept: %d live, %d idle", left, idleCount(c))
	}
}

// sing-box gives a dial no deadline of its own past the TCP connect: while
// the request still waits, its handshake must not be cut by the bound meant
// for abandoned ones.
func TestWaitingRequestsHandshakeIsNotBounded(t *testing.T) {
	dial, _ := slowDial(t, 400*time.Millisecond)
	c := newTestClient(dial, false)
	c.abandonedDial = 100 * time.Millisecond
	defer c.Close()

	st, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("a handshake the request was still waiting for was cut: %v", err)
	}
	st.Close()
}

// A handshake its request gave up on is bounded: it does not hang on for a
// dead path until TCP gives up.
func TestAbandonedHandshakeIsBounded(t *testing.T) {
	cancelled := make(chan struct{})
	dial := func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done() // a path that never completes a handshake
		close(cancelled)
		return nil, ctx.Err()
	}
	c := newTestClient(dial, false)
	c.abandonedDial = 200 * time.Millisecond
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _ = c.CreateStream(ctx)
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("an abandoned handshake was never cancelled")
	}
}

// A session that closed before it reached the pool - a handshake finishing
// just as the peer drops the connection - must not be pooled after its close
// hook ran: the next request would take it and fail instead of dialling.
func TestClosedSessionIsNotPooled(t *testing.T) {
	dial, dials := slowDial(t, 0)
	c := newTestClient(dial, false)
	defer c.Close()

	session, err := c.dialSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session.Close()
	c.keepIdle(session)
	if n := idleCount(c); n != 0 {
		t.Fatalf("%d closed session(s) pooled", n)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	st, err := c.CreateStream(ctx)
	if err != nil {
		t.Fatalf("the next request failed instead of dialling: %v", err)
	}
	st.Close()
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialled %d times, want a new session for the next request", n)
	}
}

// A pooled session that closed while its close hook has yet to remove it is
// passed over, not handed to a request.
func TestIdleSessionClosedInThePoolIsSkipped(t *testing.T) {
	dial, _ := slowDial(t, 0)
	c := newTestClient(dial, false)
	defer c.Close()

	conn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session := NewClientSession(conn, defaultPadding(), logger.NOP())
	session.seq = c.sessionCounter.Add(1)
	c.idleSessionLock.Lock()
	c.idleSession.Insert(math.MaxUint64-session.seq, session)
	c.idleSessionLock.Unlock()
	session.Close() // no hook: still in the pool, as in the window before it runs

	if got := c.getIdleSession(); got != nil {
		t.Fatal("a closed session was taken from the pool")
	}
}
