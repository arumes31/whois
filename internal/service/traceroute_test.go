package service

import (
	"context"
	"testing"
)

func TestTraceroute_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Traceroute(ctx, "8.8.8.8", func(line string) {})
}

func TestTraceroute_InvalidTarget(t *testing.T) {
	Traceroute(context.Background(), "invalid!target", func(line string) {})
}
