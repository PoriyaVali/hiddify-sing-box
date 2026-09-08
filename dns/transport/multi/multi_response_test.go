package multi

import (
	"context"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"net"
	"net/netip"
	"testing"
	"time"
)

type responseTestTransport struct {
	dns.TransportAdapter
	response *D.Msg
	delay    time.Duration
}

func (*responseTestTransport) Start(adapter.StartStage) error { return nil }
func (*responseTestTransport) Close() error                   { return nil }
func (*responseTestTransport) Reset()                         {}
func (t *responseTestTransport) Exchange(ctx context.Context, _ *D.Msg) (*D.Msg, error) {
	select {
	case <-time.After(t.delay):
		return t.response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestBlockedCNAMECannotCancelHealthyAnswer(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		q := new(D.Msg)
		q.SetQuestion("www.invalid.", D.TypeA)
		bad := new(D.Msg)
		bad.SetReply(q)
		bad.Answer = []D.RR{&D.CNAME{Hdr: D.RR_Header{Name: "www.invalid.", Rrtype: D.TypeCNAME}, Target: "alias.invalid."}, &D.A{Hdr: D.RR_Header{Name: "alias.invalid.", Rrtype: D.TypeA}, A: net.IPv4(198, 18, 0, 5)}}
		good := new(D.Msg)
		good.SetReply(q)
		good.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: "www.invalid.", Rrtype: D.TypeA}, A: net.IPv4(203, 0, 113, 5)}}
		m := &Transport{parallel: parallel, done: make(chan struct{}), logger: log.NewNOPFactory().Logger(), ignoredRanges: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}, transports: []adapter.DNSTransport{&responseTestTransport{response: bad}, &responseTestTransport{response: good, delay: 10 * time.Millisecond}}}
		got, err := m.Exchange(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Answer) != 1 || got.Answer[0].(*D.A).A.String() != "203.0.113.5" {
			t.Fatalf("parallel=%v: %v", parallel, got)
		}
		if len(bad.Answer) != 2 {
			t.Fatal("shared response mutated")
		}
	}
}

func TestNegativeDNSAndLANArePreserved(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("lan.invalid.", D.TypeA)
	for _, negative := range []bool{false, true} {
		r := new(D.Msg)
		r.SetReply(q)
		if negative {
			r.Rcode = D.RcodeNameError
		} else {
			r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: "lan.invalid.", Rrtype: D.TypeA}, A: net.IPv4(192, 168, 1, 2)}}
		}
		m := &Transport{parallel: true, done: make(chan struct{}), logger: log.NewNOPFactory().Logger(), transports: []adapter.DNSTransport{&responseTestTransport{response: r}}}
		got, err := m.Exchange(context.Background(), q)
		if err != nil || got.Rcode != r.Rcode || len(got.Answer) != len(r.Answer) {
			t.Fatalf("negative=%v: %v %v", negative, got, err)
		}
	}
}
