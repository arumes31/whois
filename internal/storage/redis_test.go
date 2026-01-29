package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"
	"whois/internal/model"
	"whois/internal/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func init() {
	utils.TestInitLogger()
}

func setupMiniredis(t *testing.T) *Storage {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	return &Storage{Client: client}
}

func TestStorage_Basic(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()

	// Test Monitored Items
	item := "test-domain.com"
	if err := s.AddMonitoredItem(ctx, item); err != nil {
		t.Fatalf("failed to add item: %v", err)
	}

	items, err := s.GetMonitoredItems(ctx)
	if err != nil {
		t.Fatalf("failed to get items: %v", err)
	}
	if len(items) != 1 || items[0] != item {
		t.Errorf("GetMonitoredItems mismatch: got %v, want [%s]", items, item)
	}

	if err := s.RemoveMonitoredItem(ctx, item); err != nil {
		t.Fatalf("failed to remove item: %v", err)
	}
	items, _ = s.GetMonitoredItems(ctx)
	if len(items) != 0 {
		t.Errorf("expected 0 items after removal, got %d", len(items))
	}
}

func TestStorage_Cache(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()

	key := "test-key"
	val := map[string]string{"foo": "bar"}

	err := s.SetCache(ctx, key, val, 1*time.Minute)
	if err != nil {
		t.Fatalf("SetCache failed: %v", err)
	}

	cached, err := s.GetCache(ctx, key)
	if err != nil {
		t.Fatalf("GetCache failed: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(cached), &result); err != nil {
		t.Fatalf("failed to unmarshal cache: %v", err)
	}
	if result["foo"] != "bar" {
		t.Errorf("cache value mismatch: got %v", result)
	}

	// Test cache miss
	_, err = s.GetCache(ctx, "non-existent")
	if err != redis.Nil {
		t.Errorf("expected redis.Nil for cache miss, got %v", err)
	}
}

func TestStorage_DNSHistory(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	target := "example.com"

	// 1. First Entry
	res1 := map[string]string{"A": "1.1.1.1"}
	if err := s.AddDNSHistory(ctx, target, res1); err != nil {
		t.Fatalf("AddDNSHistory 1 failed: %v", err)
	}

	// 2. Duplicate Entry (should be skipped)
	if err := s.AddDNSHistory(ctx, target, res1); err != nil {
		t.Fatalf("AddDNSHistory duplicate failed: %v", err)
	}

	history, err := s.GetDNSHistory(ctx, target)
	if err != nil {
		t.Fatalf("GetDNSHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(history))
	}

	// 3. New Entry
	res2 := map[string]string{"A": "2.2.2.2"}
	if err := s.AddDNSHistory(ctx, target, res2); err != nil {
		t.Fatalf("AddDNSHistory 2 failed: %v", err)
	}

	history, _ = s.GetDNSHistory(ctx, target)
	if len(history) != 2 {
		t.Errorf("Expected 2 history entries, got %d", len(history))
	}

	// Test GetHistoryWithDiffs
	entries, diffs, err := s.GetHistoryWithDiffs(ctx, target)
	if err != nil {
		t.Fatalf("GetHistoryWithDiffs failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
	if len(diffs) != 1 {
		t.Errorf("Expected 1 diff, got %d", len(diffs))
	}

	// Test with single entry diff
	_ = s.Client.Del(ctx, "dns_history:"+target)
	_ = s.AddDNSHistory(ctx, target, res1)
	_, diffs, _ = s.GetHistoryWithDiffs(ctx, target)
	if len(diffs) != 0 {
		t.Error("Expected 0 diffs for single entry")
	}

	// Test 'No changes' diff
	_ = s.AddDNSHistory(ctx, target, res2)
	// We need to manually add another entry with same result to trigger 'No changes' branch
	// because AddDNSHistory normally skips duplicates.
	entry := model.HistoryEntry{Timestamp: "now", Result: "{\"A\":\"2.2.2.2\"}"}
	b, _ := json.Marshal(entry)
	_ = s.Client.LPush(ctx, "dns_history:"+target, string(b))
	_, diffs, _ = s.GetHistoryWithDiffs(ctx, target)
	foundNoChanges := false
	for _, d := range diffs {
		if d == "No changes" {
			foundNoChanges = true
			break
		}
	}
	if !foundNoChanges {
		t.Error("Expected 'No changes' in diffs")
	}
}

func TestStorage_Errors(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := &Storage{Client: client}
	ctx := context.Background()

	mr.Close() // Force connection error

	_, err = s.GetMonitoredItems(ctx)
	if err == nil {
		t.Error("Expected error from closed redis")
	}

	_, err = s.GetDNSHistory(ctx, "test")
	if err == nil {
		t.Error("Expected error from closed redis in GetDNSHistory")
	}

	_, err = s.GetCache(ctx, "test")
	if err == nil {
		t.Error("Expected error from closed redis in GetCache")
	}

	_, _, err = s.GetHistoryWithDiffs(ctx, "test")
	if err == nil {
		t.Error("Expected error from closed redis in GetHistoryWithDiffs")
	}
}

func TestStorage_History_NoChanges(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	target := "test.com"

	res := map[string]string{"A": "1.2.3.4"}
	_ = s.AddDNSHistory(ctx, target, res)
	_ = s.AddDNSHistory(ctx, target, res) // Duplicate

	// Add entry with same result but manual list manipulation to test logic branch
	entry := model.HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    "{\"A\":\"1.2.3.4\"}",
	}
	b, _ := json.Marshal(entry)
	_ = s.Client.LPush(ctx, "dns_history:"+target, string(b))

	// AddDNSHistory should skip if same
	_ = s.AddDNSHistory(ctx, target, res)

	h, _ := s.GetDNSHistory(ctx, target)
	if len(h) != 2 { // One from manual LPush, one from first AddDNSHistory
		t.Errorf("Expected 2 history entries, got %d", len(h))
	}
}

func TestStorage_Stats(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()

	_ = s.AddMonitoredItem(ctx, "item1")
	_ = s.AddDNSHistory(ctx, "host1", "data")
	_ = s.AddDNSHistory(ctx, "host2", "data")

	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}
	if stats.MonitoredCount != 1 {
		t.Errorf("Expected 1 monitored item, got %d", stats.MonitoredCount)
	}
	if stats.HistoryCount != 2 {
		t.Errorf("Expected 2 history keys, got %d", stats.HistoryCount)
	}
}

func TestNewStorage(t *testing.T) {
	s := NewStorage("localhost", "6379")
	if s.Client == nil {
		t.Error("Storage client should not be nil")
	}
}
