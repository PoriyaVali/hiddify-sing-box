package session

import "time"

// clockOrigin anchors the session's timestamps. Durations measured from it
// come from the monotonic clock, so a wall-clock correction - NTP, or a phone
// taking the network's time - neither stretches nor shrinks them, as
// differences of UnixNano readings would: a forward correction made a session
// whose write was still moving look stalled, and closed it.
var clockOrigin = time.Now()

// monoNow is the time since clockOrigin in nanoseconds. Never zero, which
// marks "unset" in the fields that hold it.
func monoNow() int64 { return int64(time.Since(clockOrigin)) + 1 }
