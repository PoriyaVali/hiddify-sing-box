package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func ipTestMonitor(t *testing.T, lookup func(context.Context, N.Dialer) (*ipinfo.IpInfo, error)) *OutboundMonitoring {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	m := testMonitor(t, "", nil, &fakeOutbound{tag: "node"})
	m.transferEndpoints = nil
	m.urls = []string{server.URL + "/generate_204"}
	m.urlTestTimeout = 5 * time.Second
	m.ipSlots = make(chan struct{}, 4)
	m.ipLookup = lookup
	m.outbounds["node"].history = adapter.URLTestHistory{}
	return m
}

func TestAFirstResultDoesNotWaitForTheIPLookup(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	m := ipTestMonitor(t, func(ctx context.Context, _ N.Dialer) (*ipinfo.IpInfo, error) {
		select {
		case <-release:
			return &ipinfo.IpInfo{IP: "203.0.113.7", CountryCode: "DE"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	start := time.Now()
	his, err := m.tester(m.ctx, "node")
	require.NoError(t, err)
	require.Less(t, time.Since(start), 2*time.Second, "the result waited for the IP lookup")
	require.Less(t, his.Delay, TimeoutDelay)
	require.Nil(t, his.IpInfo, "the lookup has not answered yet")

	close(release)
	state := m.outbounds["node"]
	require.Eventually(t, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.IpInfo != nil && state.history.IpInfo.CountryCode == "DE"
	}, 5*time.Second, 10*time.Millisecond, "the IP information never reached the node's row")
}

func TestOneIPLookupPerNodeAndNoneOnceKnown(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	release := make(chan struct{})
	m := ipTestMonitor(t, func(ctx context.Context, _ N.Dialer) (*ipinfo.IpInfo, error) {
		calls.Add(1)
		select {
		case <-release:
			return &ipinfo.IpInfo{IP: "203.0.113.7", CountryCode: "DE"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	for i := 0; i < 3; i++ {
		_, err := m.tester(m.ctx, "node")
		require.NoError(t, err)
	}
	close(release)
	state := m.outbounds["node"]
	require.Eventually(t, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.IpInfo != nil && !state.ipLookupRunning
	}, 5*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 1, calls.Load(), "three tests while a lookup ran started more than one")

	_, err := m.tester(m.ctx, "node")
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, 1, calls.Load(), "a node whose IP is known was looked up again")
}

func TestCachedIPInformationIsRefreshedOnce(t *testing.T) {
	t.Parallel()
	m := ipTestMonitor(t, func(context.Context, N.Dialer) (*ipinfo.IpInfo, error) {
		return &ipinfo.IpInfo{IP: "203.0.113.8", CountryCode: "NL"}, nil
	})
	state := m.outbounds["node"]
	state.history.IpInfo = &ipinfo.IpInfo{IP: "198.51.100.1", CountryCode: "FR"}
	state.from_cache = true

	_, err := m.tester(m.ctx, "node")
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.history.IpInfo.CountryCode == "NL"
	}, 5*time.Second, 10*time.Millisecond, "a cached IP was not refreshed by the first live test")
}

func TestAFailedURLTestStartsNoIPLookup(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	m := ipTestMonitor(t, func(context.Context, N.Dialer) (*ipinfo.IpInfo, error) {
		calls.Add(1)
		return nil, context.Canceled
	})
	m.urls = []string{"http://127.0.0.1:1/generate_204"}
	his, err := m.tester(m.ctx, "node")
	require.Error(t, err)
	require.Equal(t, TimeoutDelay, his.Delay)
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, calls.Load())
}
