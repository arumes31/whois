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
	t.Parallel()
	// Setup environment
	_ = os.Setenv("SECRET_KEY", "test-secret")
	defer os.Unsetenv("SECRET_KEY")

	// Change to project root so templates can be found
	_ = os.Chdir("../../")

	utils.InitLogger()
	cfg, _ := config.LoadConfig()
	
	e := NewServer(cfg)
	if e == nil {
		t.Fatal("NewServer returned nil")
	}

	// Test a basic route to ensure templates are loaded and middleware works
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "INTEL GATHERING") {
		t.Error("Body missing expected title, check template loading")
	}
}
