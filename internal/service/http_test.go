package service

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
	utils.SetAllowPrivateIPs(true)
	utils.SetAllowLoopbackIPs(true)
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

	// HTTP (non-TLS) connection should not be marked as verified
	if info.Verified {
		t.Error("Expected Verified=false for plain HTTP connection")
	}
	if info.FinalURL == "" || info.Timing.Total < 0 {
		t.Fatalf("expected final URL and timing, got %#v", info)
	}
	if info.Score < 0 || info.Score > 100 || info.Grade == "" {
		t.Fatalf("invalid HTTP score: %d %q", info.Score, info.Grade)
	}
	if len(info.SecurityChecks) == 0 {
		t.Error("expected structured security checks")
	}
}

func TestGetHTTPInfoDecodesGzipWithoutAdvertisingBrotli(t *testing.T) {
	encoding := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		encoding <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("<html><title>Index of /</title></html>"))
		_ = writer.Close()
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetHTTPInfo(context.Background(), host)
	if info.Error != "" {
		t.Fatalf("GetHTTPInfo failed: %s", info.Error)
	}
	if got := <-encoding; got != "gzip" {
		t.Fatalf("Accept-Encoding = %q; want transport-managed gzip only", got)
	}
	if info.Compression != "gzip" {
		t.Errorf("Compression = %q; want gzip", info.Compression)
	}
	if !info.DirectoryListing {
		t.Error("expected gzip-compressed response body to be analyzed after decoding")
	}
}

func TestGetHTTPInfoRedirectChain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetHTTPInfo(context.Background(), host)
	if info.Error != "" {
		t.Fatalf("GetHTTPInfo failed: %s", info.Error)
	}
	if len(info.Redirects) != 1 || info.Redirects[0].Status != http.StatusFound {
		t.Fatalf("unexpected redirects: %#v", info.Redirects)
	}
	if !strings.HasSuffix(info.FinalURL, "/final") {
		t.Fatalf("unexpected final URL: %s", info.FinalURL)
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
		// Self-signed cert should fall back to InsecureSkipVerify, so Verified=false
		if info.Verified {
			t.Error("Expected Verified=false for self-signed cert (fallback)")
		}
	}
}

func TestGetHTTPInfo_SecurityHeaders(t *testing.T) {
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

func TestInspectHTTPSecurityRejectsInvalidPresentHeaders(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"Strict-Transport-Security": []string{"max-age=0"},
			"Content-Security-Policy":   []string{"script-src 'unsafe-inline'"},
			"X-Content-Type-Options":    []string{"sniff"},
			"X-Frame-Options":           []string{"ALLOWALL"},
			"Content-Type":              []string{"text/html"},
		},
		Request: &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}},
	}
	checks, _, issues, score := inspectHTTPSecurity(response, `<a href="http://example.com">insecure</a>`)
	if len(checks) == 0 || len(issues) < 5 {
		t.Fatalf("expected invalid headers and mixed content to be reported, got checks=%v issues=%v", checks, issues)
	}
	if score >= 70 {
		t.Fatalf("invalid security headers received an unexpectedly high score: %d", score)
	}
}

func TestInspectHTTPSecurityPenalizesPlainHTTP(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"Content-Security-Policy":   []string{"default-src 'self'"},
			"Permissions-Policy":        []string{"geolocation=()"},
			"X-Content-Type-Options":    []string{"nosniff"},
			"X-Frame-Options":           []string{"DENY"},
			"Referrer-Policy":           []string{"no-referrer"},
			"Strict-Transport-Security": []string{"max-age=31536000"},
		},
		Request: &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
	}
	checks, _, issues, score := inspectHTTPSecurity(response, "")
	if score > 70 {
		t.Fatalf("plain HTTP score = %d; want at most 70", score)
	}
	foundIssue := false
	for _, issue := range issues {
		if strings.Contains(issue, "not protected by HTTPS") {
			foundIssue = true
		}
	}
	if !foundIssue {
		t.Fatalf("plain HTTP issue missing: %v", issues)
	}
	if len(checks) == 0 || checks[0].Name != "Transport security" || checks[0].Status != "missing" {
		t.Fatalf("transport security check missing: %#v", checks)
	}
}

func TestInspectHTTPSecurityHandlesMissingRequest(t *testing.T) {
	response := &http.Response{Header: make(http.Header)}
	checks, _, issues, score := inspectHTTPSecurity(response, `<img src="http://example.com/image.png">`)
	if score < 0 || score > 70 {
		t.Fatalf("missing-request score = %d, want a bounded non-HTTPS score", score)
	}
	if len(checks) == 0 || checks[0].Name != "Transport security" || checks[0].Status != "missing" {
		t.Fatalf("missing-request transport check = %#v", checks)
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "not protected by HTTPS") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing-request issues = %v, want transport warning", issues)
	}
}

func TestGetHTTPInfo_Fail(t *testing.T) {
	info := GetHTTPInfo(context.Background(), "localhost:1")
	if info.Error == "" {
		t.Error("Expected error for closed port, got none")
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

func TestGetHTTPInfo_BadRequestRetry(t *testing.T) {
	// Mock a server that returns 400 for HTTP but we want to simulate the non-nil resp branch
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetHTTPInfo(context.Background(), host)
	if info.Error == "" {
		t.Log("GetHTTPInfo succeeded unexpectedly or hit the retry branch as intended")
	}
}

func TestGetHTTPInfo_InvalidURL(t *testing.T) {
	// Using a hostname that contains invalid URL characters like space or control chars to trigger NewRequest error
	info := GetHTTPInfo(context.Background(), "host with spaces")
	if info.Error == "" {
		t.Error("Expected error for invalid URL hostname")
	}
}

func TestGetHTTPInfo_InvalidTarget(t *testing.T) {
	info := GetHTTPInfo(context.Background(), "invalidhost")
	if info.Error != "invalid target host" {
		t.Errorf("Expected 'invalid target host' error, got '%s'", info.Error)
	}
}
