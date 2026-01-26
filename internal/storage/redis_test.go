package storage

import (
	"context"
	"testing"
	"time"
)

func TestStorage(t *testing.T) {
	// Attempt to connect to local redis or container
	s := NewStorage("localhost", "6379")
	ctx := context.Background()

	// Skip if Redis is not available
	err := s.Client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available on localhost:6379, skipping storage tests")
	}

	// Test Monitored Items
	item := "test-domain.com"
	s.AddMonitoredItem(ctx, item)
	items, _ := s.GetMonitoredItems(ctx)
	found := false
	for _, v := range items {
		if v == item { found = true; break }
	}
	if !found { t.Errorf("Item %s not found in monitored items", item) }

	s.RemoveMonitoredItem(ctx, item)

	// Test Cache
	s.SetCache(ctx, "test-key", "test-value", 1*time.Minute)
	val, err := s.GetCache(ctx, "test-key")
	if err != nil || val != "\"test-value\"" { // go-redis Marshals strings with quotes if we use SetCache interface
		t.Errorf("Cache failed: got %v, want %v", val, "test-value")
	}
}

