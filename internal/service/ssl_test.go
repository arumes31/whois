package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"whois/internal/model"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
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
	// Self-signed cert from httptest should fall back to InsecureSkipVerify
	if info.Verified {
		t.Error("Expected Verified=false for self-signed cert (fallback)")
	}
	if len(info.Chain) == 0 || info.FingerprintSHA256 == "" {
		t.Fatalf("expected certificate chain and fingerprint: %#v", info)
	}
	if info.Score < 0 || info.Score > 100 || info.Grade == "" {
		t.Fatalf("invalid TLS score: %d %q", info.Score, info.Grade)
	}
	if len(info.SupportedVersions) == 0 {
		t.Error("expected at least one supported TLS version")
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
	// We use a port that should fail immediately
	info := GetSSLInfo(context.Background(), "127.0.0.1:1")
	if info.Error == "" {
		t.Error("Expected error for closed port")
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

func TestGetSSLInfo_ReportsCertificate(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	info := GetSSLInfo(context.Background(), u.Host)
	if info.Error != "" {
		t.Fatalf("local TLS inspection failed: %v", info.Error)
	}
	if len(info.Chain) == 0 || info.FingerprintSHA256 == "" || info.PEM == "" {
		t.Fatalf("certificate details are incomplete: %#v", info)
	}
}

func TestGetSSLInfo_Versions(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint16
		want    string
	}{
		{name: "TLS12", version: tls.VersionTLS12, want: "TLS 1.2"},
		{name: "TLS13", version: tls.VersionTLS13, want: "TLS 1.3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			server.TLS = &tls.Config{MinVersion: test.version, MaxVersion: test.version}
			server.StartTLS()
			defer server.Close()

			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			info := GetSSLInfo(context.Background(), u.Host)
			if info.Error != "" {
				t.Fatalf("TLS inspection failed: %s", info.Error)
			}
			if !slices.Contains(info.SupportedVersions, test.want) {
				t.Fatalf("supported versions = %v; want %s", info.SupportedVersions, test.want)
			}
		})
	}
}

func TestScoreTLSRevokedCertificate(t *testing.T) {
	info := &model.SSLInfo{
		Verified:      true,
		HostnameValid: true,
		OCSPStapled:   true,
		OCSPStatus:    "revoked",
	}
	leaf := &x509.Certificate{NotAfter: time.Now().Add(90 * 24 * time.Hour)}

	score, grade, issues := scoreTLS(info, leaf, tls.TLS_AES_128_GCM_SHA256)
	if score != 0 || grade != "F" {
		t.Fatalf("revoked certificate scored %d/%s, want 0/F", score, grade)
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "revoked") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("revocation issue missing from %v", issues)
	}
}
