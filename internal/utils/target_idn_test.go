package utils

import (
	"strings"
	"testing"

	"whois/internal/model"
)

func TestNormalizeTargetIDN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, host, port, scheme, normalized string
	}{
		{input: "bücher.de", host: "xn--bcher-kva.de", normalized: "xn--bcher-kva.de"},
		{input: " WWW.BÜCHER.DE. ", host: "www.xn--bcher-kva.de", normalized: "www.xn--bcher-kva.de"},
		{input: "https://BÜCHER.de:8443/path?q=1#section", host: "xn--bcher-kva.de", port: "8443", scheme: "https", normalized: "xn--bcher-kva.de:8443"},
		{input: "bücher.de:00080", host: "xn--bcher-kva.de", port: "00080", normalized: "xn--bcher-kva.de:00080"},
		{input: "bücher.de/path", host: "xn--bcher-kva.de", scheme: "http", normalized: "xn--bcher-kva.de"},
		{input: "www。bücher.de。", host: "www.xn--bcher-kva.de", normalized: "www.xn--bcher-kva.de"},
		{input: "faß.de", host: "xn--fa-hia.de", normalized: "xn--fa-hia.de"},
		{input: "xn--bcher-kva.de", host: "xn--bcher-kva.de", normalized: "xn--bcher-kva.de"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(tc.input)
			if !got.Valid || !got.Networkable || got.Kind != model.TargetKindDomain || got.Input != tc.input ||
				got.Host != tc.host || got.Port != tc.port || got.Scheme != tc.scheme || got.Normalized != tc.normalized {
				t.Fatalf("NormalizeTarget(%q) = %+v", tc.input, got)
			}
			if !IsValidTarget(tc.input) {
				t.Fatalf("valid IDN rejected by service validation: %q", tc.input)
			}
		})
	}
}

func TestNormalizeTargetRejectsMalformedIDN(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"\u0301example.com", "ab\u200dcd.example", "xn--a.example", "bücher..de",
		"bücher。", "https://user:pass@bücher.de/", "https://bücher.de:65536/",
		string([]byte{0xff}) + ".example", strings.Repeat("é", 60) + ".example",
	} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(input)
			if got.Valid || got.Networkable || got.Error == "" {
				t.Fatalf("malformed IDN accepted: %+v", got)
			}
		})
	}
}

func TestNormalizeTargetIDNAPreservesIPClassification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, host, normalized string
		kind                    model.TargetKind
		loopback                bool
	}{
		{input: "１２７。０。０。１", host: "127.0.0.1", normalized: "127.0.0.1", kind: model.TargetKindIPv4, loopback: true},
		{input: "https://１２７。０。０。１:8443/", host: "127.0.0.1", normalized: "127.0.0.1:8443", kind: model.TargetKindIPv4, loopback: true},
		{input: "2001:4860:4860::8888", host: "2001:4860:4860::8888", normalized: "2001:4860:4860::8888", kind: model.TargetKindIPv6},
		{input: "https://[2001:4860:4860::8888]:443/", host: "2001:4860:4860::8888", normalized: "[2001:4860:4860::8888]:443", kind: model.TargetKindIPv6},
		{input: "::ffff:1.1.1.1", host: "1.1.1.1", normalized: "1.1.1.1", kind: model.TargetKindIPv4},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(tc.input)
			if !got.Valid || got.Kind != tc.kind || got.Host != tc.host || got.Normalized != tc.normalized ||
				len(got.IPs) != 1 || got.IPs[0].IsLoopback != tc.loopback {
				t.Fatalf("IP normalization/classification changed: %+v", got)
			}
		})
	}
}
