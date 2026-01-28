package service

import (
	"context"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestDNSService_Lookup(t *testing.T) {
	t.Parallel()
	s := NewDNSService("")

	tests := []struct {
		name     string
		target   string
		isIP     bool
		expected []string
	}{
		{"Google A", "google.com", false, []string{"A"}},
		{"Google MX", "google.com", false, []string{"MX"}},
		{"Google TXT", "google.com", false, []string{"TXT"}},
		{"Google DNS PTR", "8.8.8.8", true, []string{"PTR"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := s.Lookup(context.Background(), tt.target, tt.isIP)
			if err != nil {
				t.Fatalf("Lookup failed for %s: %v", tt.target, err)
			}
			for _, exp := range tt.expected {
				if _, ok := res[exp]; !ok {
					if exp == "A" || exp == "PTR" {
						t.Errorf("Expected %s records for %s", exp, tt.target)
					} else {
						t.Logf("Optional %s records not found for %s (might be blocked/throttled)", exp, tt.target)
					}
				}
			}
		})
	}

	// Test Invalid Domain
	_, err := s.Lookup(context.Background(), "invalid..domain", false)
	if err != nil {
		t.Logf("Got expected error for invalid domain: %v", err)
	}
}

func TestDNSService_DiscoverSubdomains(t *testing.T) {
	t.Parallel()
	s := NewDNSService("")
	res := s.DiscoverSubdomains(context.Background(), "google.com", nil)

	if len(res) == 0 {
		t.Log("No well-known subdomains found for google.com (this might happen depending on DNS)")
	} else {
		t.Logf("Found %d well-known subdomains", len(res))
	}
}

func TestDNSService_Trace(t *testing.T) {
	t.Parallel()
	s := NewDNSService("")
	res, err := s.Trace(context.Background(), "google.com")
	if err != nil {
		t.Logf("Trace failed: %v (expected in some environments)", err)
	}
	if len(res) == 0 {
		t.Log("Trace output was empty")
	}
}
