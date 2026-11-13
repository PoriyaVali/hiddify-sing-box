package tls

import (
	"context"
	"net"
	"strings"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func newTestClient(t *testing.T, options option.OutboundTLSOptions) Config {
	t.Helper()
	options.Enabled = true
	if options.ServerName == "" {
		options.ServerName = "www.example.com"
	}
	config, err := NewClientWithOptions(ClientOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Options: options,
	})
	if err != nil {
		skipWithoutUTLS(t, err)
		t.Fatal(err)
	}
	return config
}

// The uTLS cases need `-tags with_utls`, as every shipped build has.
func skipWithoutUTLS(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "uTLS is not included") {
		t.Skip(err)
	}
}

// `fragment` without `record_fragment` used to be dropped: only
// record_fragment opened the fragment wrapper.
func TestFragmentAloneWrapsTheConnection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		options option.OutboundTLSOptions
		wrapped bool
	}{
		{"std, nothing", option.OutboundTLSOptions{}, false},
		{"std, fragment", option.OutboundTLSOptions{Fragment: true}, true},
		{"std, record_fragment", option.OutboundTLSOptions{RecordFragment: true}, true},
		{"utls, fragment", option.OutboundTLSOptions{Fragment: true, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}}, true},
		{"utls, nothing", option.OutboundTLSOptions{UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			conn, err := newTestClient(t, tc.options).Client(client)
			if err != nil {
				t.Fatal(err)
			}
			_, wrapped := conn.NetConn().(*tf.Conn)
			if wrapped != tc.wrapped {
				t.Fatalf("wrapped = %v, want %v", wrapped, tc.wrapped)
			}
		})
	}
}

func TestMixedCaseSNI(t *testing.T) {
	t.Parallel()
	tricks := &option.TLSTricksOptions{MixedCaseSNI: true}
	for _, tc := range []struct {
		name    string
		options option.OutboundTLSOptions
	}{
		{"std", option.OutboundTLSOptions{TLSTricks: tricks}},
		{"utls", option.OutboundTLSOptions{TLSTricks: tricks, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			name := newTestClient(t, tc.options).ServerName()
			if name == "www.example.com" || !strings.EqualFold(name, "www.example.com") {
				t.Fatalf("server name %q, want a mixed-case www.example.com", name)
			}
		})
	}
	if name := newTestClient(t, option.OutboundTLSOptions{}).ServerName(); name != "www.example.com" {
		t.Fatalf("without the trick the name changed to %q", name)
	}
	reality := option.OutboundTLSOptions{
		TLSTricks: tricks,
		UTLS:      &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:   &option.OutboundRealityOptions{Enabled: true},
	}
	if config, err := NewUTLSClient(context.Background(), logger.NOP(), "", withServerName(reality)); err != nil {
		skipWithoutUTLS(t, err)
		t.Fatal(err)
	} else if name := config.ServerName(); name != "www.example.com" {
		t.Fatalf("REALITY name changed to %q; REALITY servers match it case-sensitively", name)
	}
	for _, name := range []string{"1.2.3.4", "2001:db8::1", "123.456"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := mixedCaseServerName(name); got != name {
				t.Fatalf("%q became %q", name, got)
			}
		})
	}
}

func withServerName(options option.OutboundTLSOptions) option.OutboundTLSOptions {
	options.Enabled = true
	options.ServerName = "www.example.com"
	return options
}
