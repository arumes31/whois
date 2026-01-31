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
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()

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
