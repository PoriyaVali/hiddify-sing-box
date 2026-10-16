package session

import (
	"sync/atomic"
	"time"
)

// A client closes a reused session when the server does not acknowledge a new
// stream (SYNACK) in time. A session that died while it sat in the pool - a
// NAT that dropped it, a server that restarted - would otherwise hold the
// user's request until TCP gave up. Upstream allows a fixed three seconds.
// Over a mobile link with a 300 ms round trip and bursty loss, a SYN or its
// SYNACK lost once or twice to retransmission backoff takes longer than that
// on a perfectly live session, and closing it fails the request and forces a
// new TLS handshake over the same weak link. So the allowance follows how long
// this client's acknowledgements actually take.
const (
	synTimeoutMin = 3 * time.Second
	synTimeoutMax = 12 * time.Second
)

// synRTT tracks how long the server takes to acknowledge new streams, across
// every session of one client. It leans slow: a slower sample is taken at
// once, a faster one pulls the estimate down by a quarter of the gap, so a
// few quick acknowledgements right after a stall do not shrink the allowance
// before the link has settled.
// sentSYN is a session's latest SYN: its stream, and when it was sent
// (monoNow). Only that stream's SYNACK is timed against it.
type sentSYN struct {
	sid uint32
	at  int64
}

type synRTT struct {
	est atomic.Int64 // nanoseconds; 0 before the first sample
}

func (r *synRTT) observe(d time.Duration) {
	if r == nil || d <= 0 {
		return
	}
	for {
		old := r.est.Load()
		next := int64(d)
		if old > next {
			next = old - (old-next)/4
		}
		if r.est.CompareAndSwap(old, next) {
			return
		}
	}
}

// timeout is how long a reused session may take to acknowledge a new stream:
// twice the estimate plus a second, within [synTimeoutMin, synTimeoutMax].
func (r *synRTT) timeout() time.Duration {
	if r == nil {
		return synTimeoutMin
	}
	d := 2*time.Duration(r.est.Load()) + time.Second
	if d < synTimeoutMin {
		return synTimeoutMin
	}
	if d > synTimeoutMax {
		return synTimeoutMax
	}
	return d
}
