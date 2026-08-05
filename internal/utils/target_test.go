package utils

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"whois/internal/model"
)

type fakeTargetResolver struct {
	addresses    []netip.Addr
	reverseCalls int
	lookupAddr   func(context.Context, string) ([]string, error)
}

func (r *fakeTargetResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

func (r *fakeTargetResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	r.reverseCalls++
	return r.lookupAddr(ctx, address)
}

func TestNormalizeTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		kind       model.TargetKind
		normalized string
		valid      bool
	}{
		{name: "url strips path", input: "https://Example.COM:8443/a/b?q=1#x", kind: model.TargetKindDomain, normalized: "example.com:8443", valid: true},
		{name: "bare domain path", input: "example.com/docs", kind: model.TargetKindDomain, normalized: "example.com", valid: true},
		{name: "ipv4", input: "8.8.8.8", kind: model.TargetKindIPv4, normalized: "8.8.8.8", valid: true},
		{name: "ipv6", input: "2001:4860:4860::8888", kind: model.TargetKindIPv6, normalized: "2001:4860:4860::8888", valid: true},
		{name: "cidr masks host bits", input: "192.0.2.25/24", kind: model.TargetKindCIDR, normalized: "192.0.2.0/24", valid: true},
		{name: "asn", input: "as64512", kind: model.TargetKindASN, normalized: "AS64512", valid: true},
		{name: "reject credentials", input: "https://user:pass@example.com", kind: model.TargetKindUnknown, valid: false},
		{name: "reject scheme", input: "ftp://example.com/file", kind: model.TargetKindUnknown, valid: false},
		{name: "reject label", input: "bad_label.example", kind: model.TargetKindUnknown, valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(test.input)
			if got.Valid != test.valid || got.Kind != test.kind || got.Normalized != test.normalized {
				t.Fatalf("NormalizeTarget(%q) = valid %v kind %q normalized %q; want %v %q %q", test.input, got.Valid, got.Kind, got.Normalized, test.valid, test.kind, test.normalized)
			}
		})
	}
}

func TestNormalizeTargetClassifiesSpecialAddresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input         string
		expectedScope string
	}{
		{input: "100.64.0.1", expectedScope: "carrier-grade NAT"},
		{input: "192.0.2.1", expectedScope: "documentation"},
		{input: "127.0.0.1", expectedScope: "loopback"},
		{input: "10.0.0.1", expectedScope: "private"},
	}
	for _, test := range tests {
		t.Run(test.expectedScope, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(test.input)
			if len(got.IPs) != 1 || got.IPs[0].Scope != test.expectedScope || !got.IPs[0].IsBogon {
				t.Fatalf("unexpected classification: %#v", got.IPs)
			}
		})
	}
}

func TestEnrichTargetBoundsReverseDNSLookups(t *testing.T) {
	addresses := make([]netip.Addr, 12)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
	}
	resolver := &fakeTargetResolver{
		addresses: addresses,
		lookupAddr: func(context.Context, string) ([]string, error) {
			return []string{"one.example.", "two.example."}, nil
		},
	}

	got := enrichTarget(context.Background(), "example.test", resolver, time.Second)
	if len(got.IPs) != len(addresses) {
		t.Fatalf("resolved address count = %d, want %d", len(got.IPs), len(addresses))
	}
	if resolver.reverseCalls != maxReverseDNSLookups {
		t.Fatalf("reverse lookup calls = %d, want %d", resolver.reverseCalls, maxReverseDNSLookups)
	}
	if len(got.IPs[maxReverseDNSLookups-1].ReverseDNS) != 2 || len(got.IPs[maxReverseDNSLookups].ReverseDNS) != 0 {
		t.Fatalf("reverse DNS limit was not applied: %#v", got.IPs)
	}
	if !warningsContain(got.Warnings, "limited to the first 8 addresses") {
		t.Fatalf("missing reverse lookup limit warning: %v", got.Warnings)
	}
}

func TestEnrichTargetReverseDNSTimeout(t *testing.T) {
	resolver := &fakeTargetResolver{
		lookupAddr: func(ctx context.Context, address string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	started := time.Now()
	got := enrichTarget(context.Background(), "203.0.113.1", resolver, 10*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("reverse lookup ignored timeout and took %s", elapsed)
	}
	if resolver.reverseCalls != 1 {
		t.Fatalf("reverse lookup calls = %d, want 1", resolver.reverseCalls)
	}
	if !warningsContain(got.Warnings, context.DeadlineExceeded.Error()) {
		t.Fatalf("missing timeout warning: %v", got.Warnings)
	}
}

func TestEnrichTargetHonorsCanceledContext(t *testing.T) {
	resolver := &fakeTargetResolver{
		lookupAddr: func(context.Context, string) ([]string, error) {
			t.Fatal("reverse lookup called after cancellation")
			return nil, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := enrichTarget(ctx, "203.0.113.1", resolver, time.Second)
	if !warningsContain(got.Warnings, context.Canceled.Error()) {
		t.Fatalf("missing cancellation warning: %v", got.Warnings)
	}
}

func warningsContain(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
