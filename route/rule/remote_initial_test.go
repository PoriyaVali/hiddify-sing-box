package rule

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"strings"
	"testing"
	"time"
)

type offlineTestOutbound struct{ adapter.Outbound }

func (offlineTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("mock offline; no socket opened")
}

type offlineTestManager struct{ adapter.OutboundManager }

func (offlineTestManager) Default() adapter.Outbound { return offlineTestOutbound{} }

func TestUncachedRemoteSetCannotStartEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &RemoteRuleSet{ctx: ctx, cancel: cancel, outbound: offlineTestManager{}, logger: log.NewNOPFactory().Logger(), options: option.RuleSet{Tag: "geosite-ir", RemoteOptions: option.RemoteRuleSet{URL: "https://rules.invalid/test.srs"}}, updateInterval: time.Hour}
	defer s.Close()
	err := s.StartContext(ctx, nil)
	if err == nil || !strings.Contains(err.Error(), "initial rule-set: geosite-ir") {
		t.Fatalf("empty set accepted: %v", err)
	}
}
