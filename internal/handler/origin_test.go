package handler

import (
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
			host:       "internal-service",
			origin:     "https://example.com",
			headers:    map[string]string{"X-Forwarded-Host": "example.com"},
			want:       true,
		},
		{
			name:          "Subdomain of allowed domain",
			allowedDomain: "example.com",
			host:          "localhost",
			origin:        "https://sub.example.com",
			want:          true,
		},
		{
			name:          "Exact allowed domain",
			allowedDomain: "example.com",
			host:          "localhost",
			origin:        "https://example.com",
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
			host:          "internal-ip",
			origin:        "https://whois-dev.reitetschlaeger.com",
			headers: map[string]string{
				"CF-Connecting-IP": "1.2.3.4",
				"X-Forwarded-Host": "whois-dev.reitetschlaeger.com",
			},
			want: true,
		},
		{
			name:       "Proxy Host mismatch, X-Forwarded-Host match",
			trustProxy: true,
			host:       "localhost:5000",
			origin:     "https://whois-dev.reitetschlaeger.com",
			headers:    map[string]string{"X-Forwarded-Host": "whois-dev.reitetschlaeger.com"},
			want:       true,
		},
		{
			name:   "Localhost fallback",
			host:   "localhost",
			origin: "http://localhost:5000",
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
			}
			h := NewHandler(store, cfg)

			req := httptest.NewRequest("GET", "/ws", nil)
			req.Host = tt.host
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
