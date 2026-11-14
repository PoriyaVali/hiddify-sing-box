package tls

import (
	"math/rand/v2"
	"net/netip"
)

// mixedCaseServerName implements hiddify's `tls_tricks.mixedcase_sni` (the
// app's "TLS tricks -> mixed SNI case" switch), which was declared but never
// read: it randomises the letter case of the server name sent in the
// ClientHello so a censor matching names case-sensitively misses it. DNS names
// are case-insensitive and certificate checks fold case, so the server and the
// verification are unaffected.
//
// The name is drawn once per outbound, not per connection, because the TLS
// session cache is keyed by the server name: a fresh spelling on every dial
// would turn every resumption into a full handshake.
func mixedCaseServerName(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return name
	}
	mixed := []byte(name)
	letters := 0
	for i, c := range mixed {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
			letters++
			if rand.IntN(2) == 0 {
				mixed[i] = c ^ 0x20
			}
		}
	}
	if letters == 0 {
		return name
	}
	if string(mixed) == name {
		// Make sure at least one letter changed.
		for i, c := range mixed {
			if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
				mixed[i] = c ^ 0x20
				break
			}
		}
	}
	return string(mixed)
}
