package clashapi

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type localProbeOutbound struct {
	adapter.Outbound
	address string
}

func (p *localProbeOutbound) Tag() string { return "synthetic-node" }
func (p *localProbeOutbound) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, p.address)
}

type testRoots struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (r testRoots) Pool() *x509.CertPool { return r.pool }

// Real handler, real local TLS and HTTP, no real proxy, carrier or public request.
func TestProxyDelayHonoursExpectedStatus(t *testing.T) {
	for _, status := range []int{204, 302, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(2 * time.Millisecond)
				w.WriteHeader(status)
			}))
			defer endpoint.Close()
			pool := x509.NewCertPool()
			pool.AddCert(endpoint.Certificate())
			ctx := service.ContextWith[adapter.CertificateStore](context.Background(), testRoots{pool: pool})
			ctx = context.WithValue(ctx, CtxKeyProxy, &localProbeOutbound{address: endpoint.Listener.Addr().String()})
			req := httptest.NewRequest(http.MethodGet, "/delay?timeout=3000&expected=204&url="+url.QueryEscape(endpoint.URL), nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			getProxyDelay(&Server{urlTestHistory: urltest.NewHistoryStorage()})(rec, req)
			want := http.StatusServiceUnavailable
			if status == 204 {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("status=%d code=%d body=%s", status, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProxyDelayRejectsInvalidExpectedBeforeDial(t *testing.T) {
	rec := httptest.NewRecorder()
	getProxyDelay(nil)(rec, httptest.NewRequest(http.MethodGet, "/delay?expected=oops&timeout=3000", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}
