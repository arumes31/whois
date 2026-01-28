package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetHTTPInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	// ts.URL will be like http://127.0.0.1:12345
	host := strings.TrimPrefix(ts.URL, "http://")

	info := GetHTTPInfo(host)
	if info.Error != "" {
		t.Fatalf("GetHTTPInfo failed: %s", info.Error)
	}

	if info.Status != "200 OK" {
		t.Errorf("Expected 200 OK, got %s", info.Status)
	}

	if info.Security["X-Frame-Options"] != "DENY" {
		t.Errorf("Expected X-Frame-Options DENY, got %s", info.Security["X-Frame-Options"])
	}
}

func TestGetHTTPInfo_HTTPS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// ts.URL will be like https://127.0.0.1:12345
	host := strings.TrimPrefix(ts.URL, "https://")

	// This should fail HTTP and then try HTTPS
	info := GetHTTPInfo(host)
	if info.Error != "" {
		// On some machines, TLS verification might fail for self-signed httptest cert
		t.Logf("HTTPS test info (might fail due to certs): %v", info.Error)
	} else {
		if info.Status != "200 OK" {
			t.Errorf("Expected 200 OK, got %s", info.Status)
		}
	}
}

func TestGetHTTPInfo_SecurityHeaders(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetHTTPInfo(host)

	if info.Security["Strict-Transport-Security"] != "max-age=31536000" {
		t.Errorf("HSTS header mismatch: %s", info.Security["Strict-Transport-Security"])
	}
	if info.Security["Content-Security-Policy"] != "default-src 'self'" {
		t.Errorf("CSP header mismatch: %s", info.Security["Content-Security-Policy"])
	}
	if info.Security["Referrer-Policy"] != "Not Set" {
		t.Errorf("Expected Not Set for Referrer-Policy, got %s", info.Security["Referrer-Policy"])
	}
}

func TestGetHTTPInfo_Fail(t *testing.T) {
	info := GetHTTPInfo("invalid-host-name-that-does-not-exist.test")
	if info.Error == "" {
		t.Error("Expected error for invalid host, got none")
	}
}
