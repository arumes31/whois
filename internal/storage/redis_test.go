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
	_ = s.AddMonitoredItem(ctx, item)
	items, _ := s.GetMonitoredItems(ctx)
	found := false
	for _, v := range items {
		if v == item {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Item %s not found in monitored items", item)
	}

	_ = s.RemoveMonitoredItem(ctx, item)

	// Test Cache
	_ = s.SetCache(ctx, "test-key", "test-value", 1*time.Minute)
	val, err := s.GetCache(ctx, "test-key")
	if err != nil || val != "\"test-value\"" { // go-redis Marshals strings with quotes if we use SetCache interface
		t.Errorf("Cache failed: got %v, want %v", val, "test-value")
	}

	// Test DNS History
	target := "example.com"
	res1 := map[string]string{"A": "1.1.1.1"}
	res2 := map[string]string{"A": "2.2.2.2"}

	_ = s.AddDNSHistory(ctx, target, res1)
	_ = s.AddDNSHistory(ctx, target, res2)

	history, err := s.GetDNSHistory(ctx, target)
	if err != nil || len(history) < 2 {
		t.Errorf("Failed to get history: %v", err)
	}

	// Test Diffs
	_, diffs, err := s.GetHistoryWithDiffs(ctx, target)
	if err != nil || len(diffs) < 1 {
		t.Errorf("Failed to get diffs: %v", err)
	}

	// Test Stats
	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Errorf("Failed to get stats: %v", err)
	}
	if stats.HistoryCount < 1 {
		t.Errorf("Expected at least 1 history key, got %d", stats.HistoryCount)
	}
}
