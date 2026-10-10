package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRemovedRoutingEnvironmentIsNotConfiguration(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")
	// Retired environment variables are ignored, including their old validation.
	t.Setenv("ENABLE_ROUTING", "obsolete")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("removed routing flag still affects configuration: %v", err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "routing") {
		t.Fatalf("removed routing configuration is still exposed: %s", encoded)
	}
}
