package service

import (
	"context"
	"testing"
	"whois/internal/storage"
)

func TestMonitorService(t *testing.T) {
	t.Parallel()
	s := storage.NewStorage("localhost", "6379")
	ctx := context.Background()

	err := s.Client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available, skipping monitor test")
	}

	m := NewMonitorService(s, "")
	m.RunCheck(ctx, "example.com")

	// Check if history was added
	history, err := s.GetDNSHistory(ctx, "example.com")
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history: %v", err)
	}
}

func TestMonitorService_IP(t *testing.T) {
	t.Parallel()
	s := storage.NewStorage("localhost", "6379")
	ctx := context.Background()

	err := s.Client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available, skipping monitor test")
	}

	m := NewMonitorService(s, "")
	target := "8.8.8.8"
	m.RunCheck(ctx, target)

	// Check if history was added for IP
	history, err := s.GetDNSHistory(ctx, target)
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history for IP: %v", err)
	}
}
