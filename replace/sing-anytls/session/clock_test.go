package session

import (
	"strings"
	"testing"
	"time"
)

// The session clock must read the monotonic clock. A time rebuilt from
// UnixNano has no monotonic reading, so time.Since on it follows wall-clock
// corrections; a wall-clock jump itself cannot be staged in a test.
func TestSessionClockIsMonotonic(t *testing.T) {
	if !strings.Contains(clockOrigin.String(), " m=") {
		t.Fatalf("clockOrigin %v carries no monotonic reading", clockOrigin)
	}
	a := monoNow()
	time.Sleep(2 * time.Millisecond)
	b := monoNow()
	if a <= 0 || b-a < int64(time.Millisecond) {
		t.Fatalf("monoNow went %d -> %d", a, b)
	}
}
