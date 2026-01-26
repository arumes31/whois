package utils

import (
	"testing"
)

func TestIsIP(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected bool
	}{
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"example.com", false},
		{"not an ip", false},
		{123, false},
		{nil, false},
	}

	for _, tt := range tests {
		result := IsIP(tt.input)
		if result != tt.expected {
			t.Errorf("IsIP(%v) = %v; want %v", tt.input, result, tt.expected)
		}
	}
}
