package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLookupMacVendor(t *testing.T) {
	t.Parallel()
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

func TestLocalOUILookup(t *testing.T) {
	// Create fake data dir
	_ = os.MkdirAll("data", 0755)
	content := "001122     (base 16)    Local Test Vendor\n"
	_ = os.WriteFile("data/oui.txt", []byte(content), 0644)
	defer func() { _ = os.Remove("data/oui.txt") }()

	vendor, err := localOUILookup("00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("localOUILookup failed: %v", err)
	}
	if vendor != "Local Test Vendor" {
		t.Errorf("Expected Local Test Vendor, got %s", vendor)
	}
}
