package utils

import (
	"testing"

	"whois/internal/model"
)

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
