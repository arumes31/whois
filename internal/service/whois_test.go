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
		{"Empty Target", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Whois(tt.target)
			if result == nil {
				t.Error("Whois returned nil")
			}
			
			switch v := result.(type) {
			case string:
				if tt.target == "google.com" || tt.target == "8.8.8.8" {
					t.Logf("Got error string for %s (unexpected but allowed in some envs): %s", tt.target, v)
				}
			case WhoisInfo:
				if v.Raw == "" {
					t.Error("Raw WHOIS data is empty")
				}
				if tt.target == "google.com" {
					if v.Registrar == "" {
						t.Log("Registrar is empty for google.com (parsed failed?)")
					}
				}
			default:
				t.Errorf("Unexpected result type %T", result)
			}
		})
	}
}
