package service

import (
	"testing"
)

func TestDNSService_Lookup(t *testing.T) {
	s := NewDNSService()

	// Test Domain Lookup
	res, err := s.Lookup("google.com", false)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if _, ok := res["A"]; !ok {
		t.Errorf("Expected A records for google.com")
	}

	// Test IP Lookup (Reverse)
	resIP, err := s.Lookup("8.8.8.8", true)
	if err != nil {
		t.Fatalf("Reverse lookup failed: %v", err)
	}
	if _, ok := resIP["PTR"]; !ok {
		t.Errorf("Expected PTR records for 8.8.8.8")
	}
}

func TestDNSService_QueryWellKnown(t *testing.T) {
	s := NewDNSService()
	res := s.QueryWellKnown("google.com")

	if len(res) == 0 {
		t.Log("No well-known subdomains found for google.com (this might happen depending on DNS)")
	} else {
		t.Logf("Found %d well-known subdomains", len(res))
	}
}
