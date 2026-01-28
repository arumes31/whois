package utils

import (
	"testing"
)

func TestInitLogger(t *testing.T) {
	t.Parallel()
	// Should not panic
	InitLogger()
	if Log == nil {
		t.Error("Log was not initialized")
	}
}

func TestLoggerFunctions(t *testing.T) {
	InitLogger()
	// Just ensure these don't panic
	Log.Info("test info", Field("k", "v"))
	Log.Error("test error", Field("k", "v"))
}

func TestField(t *testing.T) {
	t.Parallel()
	f := Field("key", "value")
	if f.Key != "key" {
		t.Errorf("Expected key, got %s", f.Key)
	}
	if f.String != "value" && f.Interface != "value" {
		t.Errorf("Expected value, got String=%s Interface=%v", f.String, f.Interface)
	}
}
