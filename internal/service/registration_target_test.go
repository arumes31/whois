package service

import (
	"context"
	"testing"
)

func TestRegistrationTarget(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"www.example.com", "example.com"},
		{"a.b.example.co.uk", "example.co.uk"},
		{"foo.github.io", "github.io"},
		{"www.foo.blogspot.com", "blogspot.com"},
		{"a.b.city.kawasaki.jp", "city.kawasaki.jp"},
		{"WWW.BÜCHER.DE.", "xn--bcher-kva.de"},
		{"co.uk", "co.uk"},
		{"www.example.unknown-internal", "www.example.unknown-internal"},
		{"1.1.1.1", "1.1.1.1"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := registrationTarget(tc.input); got != tc.want {
				t.Errorf("registrationTarget(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestWhoisSubdomainRetainsQuery(t *testing.T) {
	old := RdapLookupFunc
	t.Cleanup(func() { RdapLookupFunc = old })
	RdapLookupFunc = func(_ context.Context, target string) (WhoisInfo, error) {
		if target != "example.com" {
			t.Errorf("RDAP target = %q; want registered domain", target)
		}
		return WhoisInfo{Raw: "{}", Domain: target, Source: "rdap"}, nil
	}
	for _, query := range []string{"www.example.com", "https://www.example.com/path", "www.example.com:443"} {
		info, ok := Whois(context.Background(), query).(WhoisInfo)
		if !ok || info.Query != query || info.Domain != "example.com" {
			t.Fatalf("subdomain registration identity lost for %q: %#v", query, info)
		}
	}
}

func TestWhoisUnicodeDomain(t *testing.T) {
	old := RdapLookupFunc
	t.Cleanup(func() { RdapLookupFunc = old })
	RdapLookupFunc = func(_ context.Context, target string) (WhoisInfo, error) {
		if target != "xn--bcher-kva.de" {
			t.Errorf("RDAP target = %q; want IDN registered domain", target)
		}
		return WhoisInfo{Raw: "{}", Domain: target, Source: "rdap"}, nil
	}
	query := "https://WWW.BÜCHER.DE:443/path"
	info, ok := Whois(context.Background(), query).(WhoisInfo)
	if !ok || info.Query != query || info.Domain != "xn--bcher-kva.de" {
		t.Fatalf("Unicode registration lookup = %#v", info)
	}
}
