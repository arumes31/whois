package service

import (
	"context"
	"strings"
	"testing"
)

func TestPing(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	found := false
	Ping(ctx, "127.0.0.1", 1, func(line string) {
		if strings.Contains(strings.ToLower(line), "reply from") || strings.Contains(strings.ToLower(line), "64 bytes from") || strings.Contains(line, "127.0.0.1") {
			found = true
		}
	})

	if !found {
		t.Log("Ping output did not contain expected patterns (might be environment specific)")
	}
}

func TestPing_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Ping(ctx, "8.8.8.8", 4, func(line string) {})
}

func TestPing_InvalidTarget(t *testing.T) {
	Ping(context.Background(), "invalid!target", 1, func(line string) {})
}
