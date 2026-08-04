package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"whois/internal/config"
	"whois/internal/utils"
)

func TestNewServer(t *testing.T) {
	// Setup environment
	_ = os.Setenv("SECRET_KEY", "test-secret")
	_ = os.Setenv("ENVIRONMENT", "development")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()
	defer func() { _ = os.Unsetenv("ENVIRONMENT") }()

	// Change to project root so templates can be found
	_ = os.Chdir("../../")

	utils.InitLogger()
	cfg, _ := config.LoadConfig()
	// Use invalid redis port to fail fast
	cfg.RedisPort = "1"

	e := NewServer(cfg)
	if e == nil {
		t.Fatal("NewServer returned nil")
	}

	// Test a basic route
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	t.Run("MetricsRejectsSpoofedForwardedIP", func(t *testing.T) {
		cfg.TrustedIPs = "127.0.0.1"
		cfg.TrustProxy = false
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("spoofed forwarding header returned %d, want 403", rec.Code)
		}
	})

	// Test Custom Error Handler
	t.Run("HTTPErrorHandler", func(t *testing.T) {
		// A POST request without CSRF token will trigger a 400 Bad Request
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "400") {
			t.Error("Error page does not contain expected status code 400")
		}
	})
}
