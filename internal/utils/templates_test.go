package utils

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestTemplateRegistry_Render(t *testing.T) {
	tmpl := template.Must(template.New("test").Parse("{{.}}"))
	reg := &TemplateRegistry{Templates: tmpl}

	buf := new(bytes.Buffer)
	err := reg.Render(buf, "test", "hello", nil)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if buf.String() != "hello" {
		t.Errorf("Expected hello, got %s", buf.String())
	}
}

func TestIsIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    interface{}
		expected bool
	}{
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"example.com", false},
		{"not an ip", false},
		{123, false},
		{nil, false},
	}

	for _, tt := range tests {
		result := IsIP(tt.input)
		if result != tt.expected {
			t.Errorf("IsIP(%v) = %v; want %v", tt.input, result, tt.expected)
		}
	}
}

func TestIsValidTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected bool
	}{
		{"google.com", true},
		{"8.8.8.8", true},
		{"sub-domain.example.co.uk", true},
		{"invalid_chars!", false},
		{"localhost", false},                       // Not contains "."
		{"127.0.0.1", true},                        // Loopback allowed for local testing
		{strings.Repeat("a", 256) + ".com", false}, // Too long
	}

	for _, tt := range tests {
		if res := IsValidTarget(tt.input); res != tt.expected {
			t.Errorf("IsValidTarget(%s) = %v; want %v", tt.input, res, tt.expected)
		}
	}
}

func TestIsTrustedIP(t *testing.T) {
	t.Parallel()
	trusted := "127.0.0.1, , 192.168.1.0/24, invalid/cidr"
	tests := []struct {
		input    string
		expected bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.5", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		if res := IsTrustedIP(tt.input, trusted); res != tt.expected {
			t.Errorf("IsTrustedIP(%s) = %v; want %v", tt.input, res, tt.expected)
		}
	}
}

func TestExtractIP(t *testing.T) {
	t.Parallel()
	e := echo.New()

	t.Run("Cloudflare", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-Connecting-IP", "1.1.1.1")
		c := e.NewContext(req, nil)
		cfg := ProxyConfig{UseCloudflare: true}
		if ip := ExtractIP(c, cfg); ip != "1.1.1.1" {
			t.Errorf("Expected 1.1.1.1, got %s", ip)
		}
	})

	t.Run("TrustProxy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "2.2.2.2, 3.3.3.3")
		c := e.NewContext(req, nil)
		cfg := ProxyConfig{TrustProxy: true}
		if ip := ExtractIP(c, cfg); ip != "2.2.2.2" {
			t.Errorf("Expected 2.2.2.2, got %s", ip)
		}
	})

	t.Run("DefaultRealIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "4.4.4.4:1234"
		c := e.NewContext(req, nil)
		cfg := ProxyConfig{}
		if ip := ExtractIP(c, cfg); ip != "4.4.4.4" {
			t.Errorf("Expected 4.4.4.4, got %s", ip)
		}
	})
}
