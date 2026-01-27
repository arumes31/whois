package utils

import (
	"testing"
)

func TestInitLogger(t *testing.T) {
	// Should not panic
	InitLogger()
	if Log == nil {
		t.Error("Log was not initialized")
	}
}

func TestField(t *testing.T) {
	f := Field("key", "value")
	if f.Key != "key" {
		t.Errorf("Expected key, got %s", f.Key)
	}
	if f.String != "value" && f.Interface != "value" {
		t.Errorf("Expected value, got String=%s Interface=%v", f.String, f.Interface)
	}
}
