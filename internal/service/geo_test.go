package service

import (
	"testing"
)

func TestGetGeoInfo(t *testing.T) {
	tests := []struct {
		target string
	}{
		{"8.8.8.8"},
		{"1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			res, err := GetGeoInfo(tt.target)
			if err != nil {
				t.Logf("GetGeoInfo failed (expected if offline): %v", err)
				return
			}
			if res.Query != tt.target {
				t.Errorf("Expected query %s, got %s", tt.target, res.Query)
			}
		})
	}
}
