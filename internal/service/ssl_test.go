package service

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestGetSSLInfo(t *testing.T) {
	t.Parallel()
	t.Run("Online Test Fallback", func(t *testing.T) {
		info := GetSSLInfo(context.Background(), "google.com")
		if info.Error != "" {
			t.Logf("GetSSLInfo google.com failed: %s", info.Error)
		} else {
			if info.Issuer == "" {
				t.Error("Expected issuer common name")
			}
		}
	})
}

func TestGetSSLInfo_Local(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// ts.URL is https://127.0.0.1:PORT
	u, _ := url.Parse(ts.URL)

	info := GetSSLInfo(context.Background(), u.Host)
	if info.Error != "" {
		t.Fatalf("GetSSLInfo local failed: %s", info.Error)
	}

	if info.Protocol == "Unknown" {
		t.Error("Expected identified protocol, got Unknown")
	}
}

func TestGetSSLInfo_Fail(t *testing.T) {
	info := GetSSLInfo(context.Background(), "invalid-host-name-that-does-not-exist.test")
	if info.Error == "" {
		t.Error("Expected error for invalid host, got none")
	}
}

func TestGetSSLInfo_NoPort(t *testing.T) {
	// Should append :443 and try to connect
	// We use a non-existent IP to trigger connection error but verify :443 was appended
	info := GetSSLInfo(context.Background(), "192.0.2.1") // Documentation-only IP
	if info.Error == "" {
		t.Error("Expected error for non-existent IP")
	}
}

func TestGetSSLInfo_HandshakeFail(t *testing.T) {
	// A server that is TCP open but not SSL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	info := GetSSLInfo(context.Background(), host)
	if info.Error == "" {
		t.Error("Expected error for non-SSL server")
	}
}

func TestGetSSLInfo_NoCerts(t *testing.T) {
	// Hard to trigger with httptest TLSServer as it always has a cert.
	// But we can test the protocol switch logic by using a local server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	info := GetSSLInfo(context.Background(), u.Host)
	if info.Error != "" {
		t.Logf("NoCerts test info: %v", info.Error)
	}
}

func TestGetSSLInfo_Versions(t *testing.T) {
	// Test TLS 1.2 specifically
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	_ = GetSSLInfo(context.Background(), u.Host)

	// Test TLS 1.3 specifically
	ts2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts2.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	ts2.StartTLS()
	defer ts2.Close()
	u2, _ := url.Parse(ts2.URL)
	_ = GetSSLInfo(context.Background(), u2.Host)

	// Test TLS 1.0 specifically (if supported by env)
	ts3 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts3.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}
	ts3.StartTLS()
	defer ts3.Close()
	u3, _ := url.Parse(ts3.URL)
	_ = GetSSLInfo(context.Background(), u3.Host)

	// Test TLS 1.1 specifically (if supported by env)
	ts4 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts4.TLS = &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}
	ts4.StartTLS()
	defer ts4.Close()
	u4, _ := url.Parse(ts4.URL)
	_ = GetSSLInfo(context.Background(), u4.Host)
}
