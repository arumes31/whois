package service

import (
	"strings"
	"testing"
)

func TestWhois(t *testing.T) {
	// Testing with a reliable domain
	result := Whois("google.com")
	if result == nil {
		t.Error("Whois returned nil")
	}
	
	if str, ok := result.(string); ok {
		if strings.Contains(str, "WHOIS error") {
			t.Errorf("Whois returned error: %s", str)
		}
	} else if info, ok := result.(WhoisInfo); ok {
		if info.Raw == "" {
			t.Error("Whois returned empty raw data")
		}
	} else {
		t.Errorf("Whois returned unknown type: %T", result)
	}
}
