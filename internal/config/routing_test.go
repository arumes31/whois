package config

import (
	"os"
	"testing"
)

func TestRoutingRequiresExplicitEnablement(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")
	for _, tc := range []struct {
		name, value string
		want        bool
		wantError   bool
	}{
		{"default disabled", "", false, false},
		{"explicitly disabled", "false", false, false},
		{"enabled", "true", true, false},
		{"invalid flag", "perhaps", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENABLE_ROUTING", tc.value)
			if tc.value == "" {
				if err := os.Unsetenv("ENABLE_ROUTING"); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := LoadConfig()
			if (err != nil) != tc.wantError {
				t.Fatalf("configuration error: %v", err)
			}
			if err == nil && cfg.EnableRouting != tc.want {
				t.Fatalf("EnableRouting=%v, want %v", cfg.EnableRouting, tc.want)
			}
		})
	}
}
