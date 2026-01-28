package service

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGetSSLInfo(t *testing.T) {
	t.Parallel()
	t.Run("Online Test Fallback", func(t *testing.T) {
		info := GetSSLInfo("google.com")
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

	info := GetSSLInfo(u.Host)
	if info.Error != "" {
		t.Fatalf("GetSSLInfo local failed: %s", info.Error)
	}

	if info.Protocol == "Unknown" {
		t.Error("Expected identified protocol, got Unknown")
	}
}

func TestGetSSLInfo_Fail(t *testing.T) {
	info := GetSSLInfo("invalid-host-that-should-fail")
	if info.Error == "" {
		t.Error("Expected error for invalid host")
	}
}
