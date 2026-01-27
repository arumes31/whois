package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupMacVendor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "001122") || strings.Contains(r.URL.Path, "00:11:22") {
			_, _ = fmt.Fprint(w, "Test Vendor")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	originalURL := MacVendorsURL
	MacVendorsURL = server.URL + "/%s"
	defer func() { MacVendorsURL = originalURL }()

	vendor, err := LookupMacVendor("00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("LookupMacVendor failed: %v", err)
	}
	if vendor != "Test Vendor" {
		t.Errorf("Expected Test Vendor, got %s", vendor)
	}

	vendor, _ = LookupMacVendor("00:00:00:00:00:00")
	if vendor != "Vendor not found" {
		t.Errorf("Expected Vendor not found, got %s", vendor)
	}
}
