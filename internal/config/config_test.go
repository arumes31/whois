package config

import (
	"os"
	"strings"
	"testing"
)

func TestGetEnv(t *testing.T) {
	_ = os.Setenv("TEST_KEY", "test_value")
	defer func() { _ = os.Unsetenv("TEST_KEY") }()

	val := getEnv("TEST_KEY", "fallback")
	if val != "test_value" {
		t.Errorf("Expected test_value, got %s", val)
	}

	val = getEnv("NON_EXISTENT", "fallback")
	if val != "fallback" {
		t.Errorf("Expected fallback, got %s", val)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		key      string
		val      string
		fallback bool
		expected bool
	}{
		{"TEST_BOOL_TRUE", "true", false, true},
		{"TEST_BOOL_1", "1", false, true},
		{"TEST_BOOL_FALSE", "false", true, false},
		{"TEST_BOOL_0", "0", true, false},
		{"NON_EXISTENT", "", true, true},
		{"NON_EXISTENT", "", false, false},
	}

	for _, tt := range tests {
		if tt.val != "" {
			_ = os.Setenv(tt.key, tt.val)
		}
		res := getEnvBool(tt.key, tt.fallback)
		if res != tt.expected {
			t.Errorf("For %s=%s (fallback %v), expected %v, got %v", tt.key, tt.val, tt.fallback, tt.expected, res)
		}
		_ = os.Unsetenv(tt.key)
	}
}

func TestLoadConfig(t *testing.T) {
	// Test failure without SECRET_KEY
	_ = os.Unsetenv("SECRET_KEY")
	_, err := LoadConfig()
	if err == nil {
		t.Error("Expected error without SECRET_KEY")
	}

	// Test success with SECRET_KEY
	_ = os.Setenv("SECRET_KEY", "test_secret")
	defer func() { _ = os.Unsetenv("SECRET_KEY") }()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.SecretKey != "test_secret" {
		t.Errorf("Expected secret_key test_secret, got %s", cfg.SecretKey)
	}

	if cfg.Port != "5000" { // Default
		t.Errorf("Expected default port 5000, got %s", cfg.Port)
	}
}

func TestLoadConfigRejectsInvalidAndWeakProductionValues(t *testing.T) {
	t.Setenv("SECRET_KEY", strings.Repeat("s", 32))
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("TRUST_PROXY", "definitely")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "TRUST_PROXY") {
		t.Fatalf("expected named invalid boolean error, got %v", err)
	}

	t.Setenv("TRUST_PROXY", "false")
	t.Setenv("PORT_SCAN_CONCURRENCY", "999")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "PORT_SCAN_CONCURRENCY") {
		t.Fatalf("expected named integer range error, got %v", err)
	}

	t.Setenv("PORT_SCAN_CONCURRENCY", "32")
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("TRUSTED_PROXIES", "not-a-network")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
		t.Fatalf("expected trusted proxy range error, got %v", err)
	}

	t.Setenv("TRUST_PROXY", "false")
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("CONFIG_USER", "admin")
	t.Setenv("CONFIG_PASS", "admin")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "CONFIG_USER") {
		t.Fatalf("expected production credential error, got %v", err)
	}
}

func TestGetEnvInt(t *testing.T) {
	t.Setenv("TEST_INT", "12")
	if got := getEnvInt("TEST_INT", 4, 1, 20); got != 12 {
		t.Fatalf("got %d; want 12", got)
	}
	t.Setenv("TEST_INT", "200")
	if got := getEnvInt("TEST_INT", 4, 1, 20); got != 4 {
		t.Fatalf("out-of-range value = %d; want fallback 4", got)
	}
	t.Setenv("TEST_INT", "bad")
	if got := getEnvInt("TEST_INT", 4, 1, 20); got != 4 {
		t.Fatalf("invalid value = %d; want fallback 4", got)
	}
}

func TestLoadConfigSecurityAndRetentionDefaults(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("SESSION_COOKIE_SECURE", "false")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionCookieSecure {
		t.Fatal("development session cookie unexpectedly secure")
	}
	if cfg.MaxWSConnections != 128 || cfg.MaxWSConnectionsPerIP != 8 {
		t.Fatalf("websocket defaults = %d/%d, want 128/8", cfg.MaxWSConnections, cfg.MaxWSConnectionsPerIP)
	}
	if cfg.DNSHistoryMaxTargets != 1000 || cfg.DNSHistoryTTLHours != 720 {
		t.Fatalf("history defaults = %d/%d, want 1000/720", cfg.DNSHistoryMaxTargets, cfg.DNSHistoryTTLHours)
	}
}

func TestLoadConfigProductionCookieIsSecureByDefault(t *testing.T) {
	t.Setenv("SECRET_KEY", strings.Repeat("s", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("CONFIG_USER", "operator")
	t.Setenv("CONFIG_PASS", "long-production-password")
	oldCookieSecure, hadCookieSecure := os.LookupEnv("SESSION_COOKIE_SECURE")
	_ = os.Unsetenv("SESSION_COOKIE_SECURE")
	t.Cleanup(func() {
		if hadCookieSecure {
			_ = os.Setenv("SESSION_COOKIE_SECURE", oldCookieSecure)
		} else {
			_ = os.Unsetenv("SESSION_COOKIE_SECURE")
		}
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SessionCookieSecure {
		t.Fatal("production session cookie is not secure by default")
	}
}

func TestLoadConfigRejectsPerIPWebSocketLimitAboveGlobal(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("MAX_WS_CONNECTIONS", "4")
	t.Setenv("MAX_WS_CONNECTIONS_PER_IP", "5")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "MAX_WS_CONNECTIONS_PER_IP") {
		t.Fatalf("expected websocket limit validation error, got %v", err)
	}
}

func TestLoadConfigValidatesAllowedDomain(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("ALLOWED_DOMAIN", "com")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "ALLOWED_DOMAIN") {
		t.Fatalf("expected allowed-domain validation error, got %v", err)
	}
	t.Setenv("ALLOWED_DOMAIN", "example.com")
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("valid allowed domain rejected: %v", err)
	}
}
