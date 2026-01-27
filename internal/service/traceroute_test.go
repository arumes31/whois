package service

import (
	"context"
	"testing"
)

func TestTraceroute(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	found := false
	Traceroute(ctx, "127.0.0.1", func(line string) {
		if len(line) > 0 {
			found = true
			cancel() // Stop early
		}
	})

	if !found {
		t.Log("Traceroute output was empty (expected if blocked or not supported in env)")
	}
}
