package service

import (
	"testing"
)

func TestWhois(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"Valid Domain", "google.com"},
		{"Valid IP", "8.8.8.8"},
		{"Invalid Target", "this.is.not.a.real.domain.at.all.nonexistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Whois(tt.target)
			if result == nil {
				t.Error("Whois returned nil")
			}
			// We don't fail on "error" strings for invalid targets because that's expected behavior
		})
	}
}
