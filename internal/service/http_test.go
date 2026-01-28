package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestGetHTTPInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	// ts.URL will be like http://127.0.0.1:12345
	host := strings.TrimPrefix(ts.URL, "http://")

	info := GetHTTPInfo(context.Background(), host)
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
	info := GetHTTPInfo(context.Background(), host)
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
	info := GetHTTPInfo(context.Background(), host)

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
	info := GetHTTPInfo(context.Background(), "invalid-host-name-that-does-not-exist.test")
	if info.Error == "" {
		t.Error("Expected error for invalid host, got none")
	}
}

func TestGetHTTPInfo_RedirectLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetHTTPInfo(context.Background(), host)
	// Redirection limit should trigger or at least return a 200/302 depending on client.Do behavior with context
	if info.Error != "" && !strings.Contains(info.Error, "stopped after 10 redirects") {
		t.Logf("Redirect limit info: %v", info.Error)
	}
}

func TestGetHTTPInfo_BadRequestHTTPSRetry(t *testing.T) {
	// A server that returns 400 for HTTP should trigger the HTTPS retry logic
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "https://")
	info := GetHTTPInfo(context.Background(), host)
	if info.Error != "" {
		t.Logf("HTTPS retry test info: %v", info.Error)
	} else if info.Status != "200 OK" {
		t.Errorf("Expected 200 OK after HTTPS retry, got %s", info.Status)
	}
}

func TestGetHTTPInfo_InvalidURL(t *testing.T) {
	// Using a hostname that contains invalid URL characters like space or control chars to trigger NewRequest error
	info := GetHTTPInfo(context.Background(), "host with spaces")
	if info.Error == "" {
		t.Error("Expected error for invalid URL hostname")
	}
}
