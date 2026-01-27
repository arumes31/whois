package config

import (
	"os"
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
