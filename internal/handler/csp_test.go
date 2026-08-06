package handler

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"whois/internal/config"
)

func TestWebSocketConnectSource(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		remoteAddr string
		tls        bool
		cfg        config.Config
		forwarded  map[string]string
		want       string
		wantOK     bool
	}{
		{name: "direct HTTP", host: "example.com", want: "ws://example.com:80", wantOK: true},
		{name: "nonstandard port", host: "example.com:14400", want: "ws://example.com:14400", wantOK: true},
		{name: "direct HTTPS", host: "example.com", tls: true, want: "wss://example.com:443", wantOK: true},
		{name: "IPv6", host: "[::1]:14400", want: "ws://[::1]:14400", wantOK: true},
		{
			name:       "trusted forwarding",
			host:       "internal:5000",
			remoteAddr: "127.0.0.1:1234",
			cfg:        config.Config{TrustProxy: true, TrustedProxies: "127.0.0.1/32"},
			forwarded:  map[string]string{"X-Forwarded-Host": "whois.example:8443", "X-Forwarded-Proto": "https"},
			want:       "wss://whois.example:8443",
			wantOK:     true,
		},
		{
			name:       "spoofed forwarding ignored",
			host:       "internal:5000",
			remoteAddr: "192.0.2.10:1234",
			cfg:        config.Config{TrustProxy: true, TrustedProxies: "127.0.0.1/32"},
			forwarded:  map[string]string{"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"},
			want:       "ws://internal:5000",
			wantOK:     true,
		},
		{name: "directive injection rejected", host: "example.com;script-src", wantOK: false},
		{name: "invalid port rejected", host: "example.com:70000", wantOK: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request.Host = test.host
			if test.remoteAddr != "" {
				request.RemoteAddr = test.remoteAddr
			}
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			for name, value := range test.forwarded {
				request.Header.Set(name, value)
			}

			got, ok := WebSocketConnectSource(request, &test.cfg)
			if ok != test.wantOK || got != test.want {
				t.Fatalf("WebSocketConnectSource() = %q, %v; want %q, %v", got, ok, test.want, test.wantOK)
			}
		})
	}
}
