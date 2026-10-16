package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/internal/skiplist"
	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex
	// idleReady is closed, and replaced, whenever a session joins the pool.
	idleReady chan struct{}

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]

	synRTT             synRTT
	abandonedDial      time.Duration // abandonedDialTimeout; tests shorten it
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool

	logger logger.Logger
}

func NewClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int,
	disableReuse bool,
) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		disableReuse:       disableReuse,
		logger:             logger,
		abandonedDial:      abandonedDialTimeout,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	c.idleReady = make(chan struct{})
	if !c.disableReuse {
		go func() {
			for {
				time.Sleep(idleSessionCheckInterval)
				c.idleCleanup()
				select {
				case <-c.die.Done():
					return
				default:
				}
			}
		}()
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	if !c.disableReuse {
		session = c.getIdleSession()
	}
	if session == nil {
		session, err = c.createSession(ctx)
	}
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err = session.OpenStream()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	stream.dieHook = func() {
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			c.keepIdle(session)
		}
	}

	return stream, nil
}

// keepIdle puts a live session in the idle pool, or closes it when reuse is
// off or the client has been closed.
//
// Whether the session is closed is checked under the pool lock. Its close
// hook removes it from the pool under the same lock, so a session that closed
// first - a handshake finishing just as the peer drops the connection - is
// never inserted after its removal, where the next request would take it and
// fail instead of dialling a new one.
func (c *Client) keepIdle(session *Session) {
	if c.disableReuse {
		session.Close()
		return
	}
	select {
	case <-c.die.Done():
		// Now client has been closed
		session.Close()
	default:
		c.idleSessionLock.Lock()
		if session.IsClosed() {
			c.idleSessionLock.Unlock()
			return
		}
		session.idleSince = time.Now()
		c.idleSession.Insert(math.MaxUint64-session.seq, session)
		close(c.idleReady)
		c.idleReady = make(chan struct{})
		c.idleSessionLock.Unlock()
	}
}

// getIdleSession takes the newest idle session, passing over any that closed
// while its close hook has yet to remove it.
func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	for !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		session := it.Value()
		c.idleSession.Remove(it.Key())
		if !session.IsClosed() {
			idle = session
			break
		}
	}
	c.idleSessionLock.Unlock()
	return
}

// abandonedDialTimeout bounds a new session's dial and handshake once the
// request that started it no longer waits for it.
const abandonedDialTimeout = 20 * time.Second

// createSession dials a new session for a request. While the request waits,
// the dial runs as it always did, bounded by the request itself. If the
// request gives up first - an app cancelling, a URL test's deadline - the
// handshake is not thrown away: over a weak link it may be most of the way
// done, and starting the next request's from nothing is what keeps such a
// link from ever having a session. It goes on, within abandonedDialTimeout,
// and the session it makes waits in the idle pool for the request that
// follows - apps and browsers retry a failed connection.
//
// While it waits, the request also takes any session that joins the pool -
// one freed by another stream, or a handshake an earlier request gave up on -
// rather than wait for its own, which then joins the pool in turn, within the
// same bound. That bound starts when the request stops waiting, not when its
// context ends: sing-box hands an outbound the connection's own context,
// which lives as long as the connection does.
func (c *Client) createSession(ctx context.Context) (*Session, error) {
	type dialed struct {
		session *Session
		err     error
	}
	done := make(chan dialed, 1)
	unwaited := make(chan struct{}) // closed when the request stops waiting
	go func() {
		dctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		defer cancel()
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-c.die.Done():
				cancel()
				return
			case <-stop:
				return
			case <-unwaited:
			}
			abandoned := time.NewTimer(c.abandonedDial)
			defer abandoned.Stop()
			select {
			case <-c.die.Done():
				cancel()
			case <-abandoned.C:
				cancel()
			case <-stop:
			}
		}()
		session, err := c.dialSession(dctx)
		done <- dialed{session, err}
	}()
	poolLater := func() {
		close(unwaited)
		go func() {
			if d := <-done; d.session != nil {
				c.keepIdle(d.session)
			}
		}()
	}
	for {
		var ready chan struct{} // nil, never ready, without a pool
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			ready = c.idleReady
			c.idleSessionLock.Unlock()
		}
		select {
		case d := <-done:
			return d.session, d.err
		case <-ready:
			if session := c.getIdleSession(); session != nil {
				poolLater()
				return session, nil
			}
			continue // another request took it
		case <-ctx.Done():
		}
		break
	}
	select {
	case d := <-done: // made it as the request gave up
		return d.session, d.err
	default:
	}
	poolLater()
	return nil, ctx.Err()
}

func (c *Client) dialSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.logger)
	session.seq = c.sessionCounter.Add(1)
	session.synRTT = &c.synRTT
	session.dieHook = func() {
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0
	var sessionToClose []*Session

	c.idleSessionLock.Lock()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
