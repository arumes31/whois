package service

import (
	"context"
	"testing"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func init() {
	utils.TestInitLogger()
}

func setupMiniredisStorage(t *testing.T) *storage.Storage {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &storage.Storage{Client: client}
}

func TestMonitorService(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := NewMonitorService(s, "8.8.8.8:53", "")
	m.RunCheck(ctx, "example.com")

	// Check if history was added
	history, err := s.GetDNSHistory(ctx, "example.com")
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history: %v", err)
	}
}

func TestMonitorService_IP(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := NewMonitorService(s, "", "")
	target := "8.8.8.8"
	m.RunCheck(ctx, target)

	// Check if history was added for IP
	history, err := s.GetDNSHistory(ctx, target)
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history for IP: %v", err)
	}
}

func TestMonitorService_ErrorPaths(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := NewMonitorService(s, "", "")

	t.Run("Invalid Target", func(t *testing.T) {
		m.RunCheck(ctx, "invalid..domain")
	})

	t.Run("Storage Error", func(t *testing.T) {
		// Mock storage error by using a closed client if possible,
		// but storage.AddDNSHistory uses Pipeline.
		// For now we just ensure it doesn't crash.
		m.RunCheck(ctx, "google.com")
	})
}
