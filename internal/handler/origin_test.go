package handler

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
	"whois/internal/config"
	"whois/internal/storage"
	"whois/internal/utils"
)

func TestCheckOrigin(t *testing.T) {
	utils.TestInitLogger()
	store := &storage.Storage{}

	tests := []struct {
		name          string
		allowedDomain string
		trustProxy    bool
		useCloudflare bool
		skipCheck     bool
		trusted       string
		remoteAddr    string
		tls           bool
		origin        string
		host          string
		headers       map[string]string
		want          bool
	}{
		{
			name:   "Empty Origin",
			host:   "example.com",
			origin: "",
			want:   true,
		},
		{
			name:   "Same host, no headers",
			host:   "example.com",
			origin: "http://example.com",
			want:   true,
		},
		{
			name:   "Mismatched host, no headers",
			host:   "example.com",
			origin: "http://other.com",
			want:   false,
		},
		{
			name:      "Skip check enabled",
			skipCheck: true,
			host:      "example.com",
			origin:    "http://other.com",
			want:      true,
		},
		{
			name:       "X-Forwarded-Host match",
			trustProxy: true,
			trusted:    "127.0.0.1/32",
			remoteAddr: "127.0.0.1:1234",
			host:       "internal-service",
			origin:     "https://example.com",
			headers: map[string]string{
				"X-Forwarded-Host":  "example.com",
				"X-Forwarded-Proto": "https",
			},
			want: true,
		},
		{
			name:       "Untrusted proxy headers ignored",
			trustProxy: true,
			trusted:    "127.0.0.1/32",
			remoteAddr: "192.0.2.10:1234",
			host:       "internal-service",
			origin:     "https://example.com",
			headers: map[string]string{
				"X-Forwarded-Host":  "example.com",
				"X-Forwarded-Proto": "https",
			},
			want: false,
		},
		{
			name:          "Subdomain of allowed domain",
			allowedDomain: "example.com",
			host:          "localhost",
			origin:        "http://sub.example.com",
			want:          true,
		},
		{
			name:          "Exact allowed domain",
			allowedDomain: "example.com",
			host:          "localhost",
			origin:        "http://example.com",
			want:          true,
		},
		{
			name:          "Mismatched allowed domain",
			allowedDomain: "example.com",
			host:          "some-server.com",
			origin:        "https://example.org",
			want:          false,
		},
		{
			name:          "Cloudflare trust",
			useCloudflare: true,
			trusted:       "127.0.0.1/32",
			remoteAddr:    "127.0.0.1:1234",
			host:          "internal-ip",
			origin:        "https://whois-dev.reitetschlaeger.com",
			headers: map[string]string{
				"CF-Connecting-IP":  "1.2.3.4",
				"X-Forwarded-Host":  "whois-dev.reitetschlaeger.com",
				"X-Forwarded-Proto": "https",
			},
			want: true,
		},
		{
			name:       "Proxy Host mismatch, X-Forwarded-Host match",
			trustProxy: true,
			trusted:    "127.0.0.1/32",
			remoteAddr: "127.0.0.1:1234",
			host:       "localhost:5000",
			origin:     "https://whois-dev.reitetschlaeger.com",
			headers: map[string]string{
				"X-Forwarded-Host":  "whois-dev.reitetschlaeger.com",
				"X-Forwarded-Proto": "https",
			},
			want: true,
		},
		{
			name:   "Exact localhost origin",
			host:   "localhost",
			origin: "http://localhost",
			want:   true,
		},
		{
			name:   "Malicious origin rejected for localhost request",
			host:   "localhost:5000",
			origin: "https://evil.example",
			want:   false,
		},
		{
			name:   "Port mismatch rejected",
			host:   "example.com:8080",
			origin: "http://example.com",
			want:   false,
		},
		{
			name:   "Scheme mismatch rejected",
			host:   "example.com",
			origin: "https://example.com",
			want:   false,
		},
		{
			name:   "TLS exact origin",
			host:   "example.com",
			origin: "https://example.com",
			tls:    true,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				AllowedDomain:   tt.allowedDomain,
				TrustProxy:      tt.trustProxy,
				UseCloudflare:   tt.useCloudflare,
				SkipOriginCheck: tt.skipCheck,
				TrustedProxies:  tt.trusted,
			}
			h := NewHandler(store, cfg)

			req := httptest.NewRequest("GET", "/ws", nil)
			req.Host = tt.host
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := h.Upgrader.CheckOrigin(req)
			if got != tt.want {
				t.Errorf("CheckOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}
