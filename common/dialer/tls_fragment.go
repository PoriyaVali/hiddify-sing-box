package dialer

import (
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Hiddify's dialer-level `tls_fragment` option (Doctor Mobile).
//
// The option was declared in option.DialerOptions but nothing read it after
// the fork moved to sing-box 1.13, so everything that relied on it went out
// unfragmented, without any error:
//
//   - the app's "TLS tricks -> fragment" switch, which hiddify-core turns into
//     this option on TLS websocket/gRPC/HTTPUpgrade outbounds;
//   - the `direct-fragment` outbound behind the "direct with fragment" routing
//     rule, the direct DoH/DoT DNS server and the WARP config detour.
//
// The shape is Xray's "tlshello", which is what the option's Size/Sleep
// settings were written for: the first write, when it carries a TLS
// ClientHello record, is re-cut into TLS records whose payload lengths are
// drawn from Size, and each record goes out in its own write with a pause
// drawn from Sleep between them. A Sleep of zero keeps the records in a single
// write (record fragmentation alone). Every later write is passed through.
//
// Go enables TCP_NODELAY on every TCP connection, so each write leaves as its
// own segment unless the congestion window makes the kernel queue it.

// Defaults for an empty or malformed range: the app's own defaults.
var (
	defaultTLSFragmentSize  = tlsFragmentRange{10, 30}
	defaultTLSFragmentSleep = tlsFragmentRange{2, 8}
)

const (
	tlsRecordHeaderLen       = 5
	tlsMaxRecordPayload      = 1 << 14
	tlsContentTypeHandshake  = 0x16
	tlsHandshakeClientHello  = 0x01
	tlsFragmentMaxSleepMilli = 1000
)

type tlsFragmentRange struct{ min, max int }

func (r tlsFragmentRange) pick() int {
	if r.max <= r.min {
		return r.min
	}
	return r.min + rand.IntN(r.max-r.min+1)
}

type tlsFragmentConfig struct {
	size  tlsFragmentRange
	sleep tlsFragmentRange
}

// newTLSFragmentConfig returns nil when the option is off. A malformed range
// falls back to the default rather than failing the whole configuration: the
// values can come from a subscription header, and refusing to start over one
// would leave the user with no connection at all.
func newTLSFragmentConfig(options option.TLSFragmentOptions) *tlsFragmentConfig {
	if !options.Enabled {
		return nil
	}
	return &tlsFragmentConfig{
		size:  parseTLSFragmentRange(options.Size, defaultTLSFragmentSize, 1, tlsMaxRecordPayload),
		sleep: parseTLSFragmentRange(options.Sleep, defaultTLSFragmentSleep, 0, tlsFragmentMaxSleepMilli),
	}
}

// parseTLSFragmentRange reads "min-max" or a single "n", the format the app
// writes. Values are clamped to [lower, upper].
func parseTLSFragmentRange(value string, fallback tlsFragmentRange, lower, upper int) tlsFragmentRange {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	first, second, hasSecond := strings.Cut(value, "-")
	from, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil {
		return fallback
	}
	to := from
	if hasSecond {
		to, err = strconv.Atoi(strings.TrimSpace(second))
		if err != nil {
			return fallback
		}
	}
	if from > to {
		from, to = to, from
	}
	clamp := func(v int) int { return min(max(v, lower), upper) }
	return tlsFragmentRange{clamp(from), clamp(to)}
}

func (c *tlsFragmentConfig) wrap(conn net.Conn) net.Conn {
	if c == nil || conn == nil {
		return conn
	}
	return &tlsFragmentConn{Conn: conn, config: c}
}

type tlsFragmentConn struct {
	net.Conn
	config *tlsFragmentConfig
	done   atomic.Bool
	mu     sync.Mutex
}

func (c *tlsFragmentConn) Write(b []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done.Load() {
		return c.Conn.Write(b)
	}
	if len(b) == 0 {
		// An empty write is how the router opens a TCP Fast Open connection
		// that has nothing to send yet (a server-first protocol): pass it on
		// and keep waiting for the ClientHello.
		return c.Conn.Write(b)
	}
	defer c.done.Store(true)
	recordLen, ok := clientHelloRecordLen(b)
	if !ok {
		return c.Conn.Write(b)
	}
	if err := c.writeRecords(b[:3], b[tlsRecordHeaderLen:recordLen]); err != nil {
		return 0, err
	}
	if len(b) > recordLen {
		n, err := c.Conn.Write(b[recordLen:])
		return recordLen + n, err
	}
	return len(b), nil
}

// clientHelloRecordLen reports the length of the TLS record at the start of b
// when it is a complete handshake record that begins a ClientHello.
func clientHelloRecordLen(b []byte) (int, bool) {
	if len(b) <= tlsRecordHeaderLen || b[0] != tlsContentTypeHandshake || b[1] != 0x03 {
		return 0, false
	}
	payloadLen := int(b[3])<<8 | int(b[4])
	if payloadLen == 0 || payloadLen > tlsMaxRecordPayload || len(b) < tlsRecordHeaderLen+payloadLen {
		return 0, false
	}
	if b[tlsRecordHeaderLen] != tlsHandshakeClientHello {
		return 0, false
	}
	return tlsRecordHeaderLen + payloadLen, true
}

func (c *tlsFragmentConn) writeRecords(header []byte, payload []byte) error {
	coalesce := c.config.sleep.max == 0
	var batch []byte
	if coalesce {
		batch = make([]byte, 0, len(payload)+tlsRecordHeaderLen*(len(payload)/max(c.config.size.min, 1)+1))
	}
	for from := 0; from < len(payload); {
		to := min(from+c.config.size.pick(), len(payload))
		record := make([]byte, 0, tlsRecordHeaderLen+to-from)
		record = append(record, header...)
		record = append(record, byte((to-from)>>8), byte(to-from))
		record = append(record, payload[from:to]...)
		from = to
		if coalesce {
			batch = append(batch, record...)
			continue
		}
		if _, err := c.Conn.Write(record); err != nil {
			return err
		}
		if from < len(payload) {
			if pause := c.config.sleep.pick(); pause > 0 {
				time.Sleep(time.Duration(pause) * time.Millisecond)
			}
		}
	}
	if coalesce {
		_, err := c.Conn.Write(batch)
		return err
	}
	return nil
}

// CloseWrite keeps TCP half-close working: the router type-asserts the
// destination itself, so without this a client that half-closes would have
// the whole connection closed and lose the rest of the server's answer.
func (c *tlsFragmentConn) CloseWrite() error {
	if closer, ok := c.Conn.(N.WriteCloser); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

// NeedHandshake passes through a TCP Fast Open connection's request for an
// early write, which the router also checks with a plain type assertion.
func (c *tlsFragmentConn) NeedHandshake() bool {
	//nolint:staticcheck // EarlyConn is what the router and slowOpenConn use.
	if early, ok := c.Conn.(N.EarlyConn); ok {
		return early.NeedHandshake()
	}
	return false
}

func (c *tlsFragmentConn) Upstream() any {
	return c.Conn
}

func (c *tlsFragmentConn) ReaderReplaceable() bool {
	return true
}

func (c *tlsFragmentConn) WriterReplaceable() bool {
	return c.done.Load()
}
