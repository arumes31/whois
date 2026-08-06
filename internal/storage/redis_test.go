package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
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

type failingSAddClient struct {
	RedisClient
}

func (c *failingSAddClient) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	cmd.SetErr(context.Canceled)
	return cmd
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

func TestStorage_AddMonitoredItemIfAbsentIsAtomic(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	const item = "example.com"

	var wg sync.WaitGroup
	results := make(chan bool, 32)
	errors := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			added, err := s.AddMonitoredItemIfAbsent(ctx, item)
			results <- added
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)

	addedCount := 0
	for added := range results {
		if added {
			addedCount++
		}
	}
	for err := range errors {
		if err != nil {
			t.Fatalf("atomic add failed: %v", err)
		}
	}
	if addedCount != 1 {
		t.Fatalf("successful inserts = %d, want 1", addedCount)
	}
	items, err := s.GetMonitoredItems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0] != item {
		t.Fatalf("monitored items = %v, want [%s]", items, item)
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

func TestStorage_SetCacheRejectsUnencodableValueBeforeMutation(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()

	if err := s.SetCache(ctx, "invalid-cache", math.NaN(), time.Minute); err == nil {
		t.Fatal("SetCache accepted an unencodable value")
	}
	if _, err := s.GetCache(ctx, "invalid-cache"); err != redis.Nil {
		t.Fatalf("cache lookup error = %v, want redis.Nil after rejected value", err)
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

func TestStorage_DNSHistoryConcurrentIdenticalWritesAreDeduplicated(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	const writers = 32

	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- s.AddDNSHistory(ctx, "concurrent.example", map[string][]string{
				"A": {"192.0.2.1"},
			})
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}

	history, err := s.GetDNSHistory(ctx, "concurrent.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("identical concurrent writes produced %d entries, want 1", len(history))
	}
}

func TestStorage_DNSHistoryRecoversFromScalarOrCorruptHead(t *testing.T) {
	tests := []struct {
		name string
		head string
	}{
		{name: "JSON null", head: "null"},
		{name: "JSON scalar", head: "42"},
		{name: "malformed JSON", head: "not-json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setupMiniredis(t)
			ctx := context.Background()
			const target = "corrupt-head.example"
			if err := s.Client.LPush(ctx, dnsHistoryKeyPrefix+target, tt.head).Err(); err != nil {
				t.Fatal(err)
			}

			if err := s.AddDNSHistory(ctx, target, map[string]string{"A": "192.0.2.1"}); err != nil {
				t.Fatalf("write after corrupt head failed: %v", err)
			}
			head, err := s.Client.LIndex(ctx, dnsHistoryKeyPrefix+target, 0).Result()
			if err != nil {
				t.Fatal(err)
			}
			var entry model.HistoryEntry
			if err := json.Unmarshal([]byte(head), &entry); err != nil {
				t.Fatalf("replacement head is not a history entry: %v", err)
			}
			if entry.Result != `{"A":"192.0.2.1"}` {
				t.Fatalf("replacement result = %q", entry.Result)
			}
		})
	}
}

func TestStorage_DNSHistoryPrunesStaleTargetsOnlyAtCapacity(t *testing.T) {
	s := setupMiniredis(t)
	s.ConfigureDNSHistory(3, time.Hour)
	ctx := context.Background()

	if err := s.Client.SAdd(ctx, dnsHistoryTargetsKey, "stale.example").Err(); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"one.example", "two.example"} {
		if err := s.AddDNSHistory(ctx, target, map[string]string{"A": "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	tracked, err := s.Client.SCard(ctx, dnsHistoryTargetsKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if tracked != 3 {
		t.Fatalf("below-capacity insertion unexpectedly pruned the stale member: count=%d", tracked)
	}

	if err := s.AddDNSHistory(ctx, "three.example", map[string]string{"A": "192.0.2.3"}); err != nil {
		t.Fatalf("capacity-edge insertion did not reclaim stale member: %v", err)
	}
	tracked, err = s.Client.SCard(ctx, dnsHistoryTargetsKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if tracked != 3 {
		t.Fatalf("tracked targets after capacity pruning = %d, want 3", tracked)
	}
	isStale, err := s.Client.(*redis.Client).SIsMember(ctx, dnsHistoryTargetsKey, "stale.example").Result()
	if err != nil {
		t.Fatal(err)
	}
	if isStale {
		t.Fatal("capacity-edge insertion left stale tracking member behind")
	}
}

func TestStorage_DNSHistoryCapacityAndTTL(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	s := &Storage{Client: redis.NewClient(&redis.Options{Addr: mr.Addr()})}
	s.ConfigureDNSHistory(2, time.Hour)
	ctx := context.Background()

	for _, target := range []string{"one.example", "two.example"} {
		if err := s.AddDNSHistory(ctx, target, map[string]string{"A": "203.0.113.1"}); err != nil {
			t.Fatalf("add %s: %v", target, err)
		}
	}
	if err := s.AddDNSHistory(ctx, "three.example", map[string]string{"A": "203.0.113.3"}); !errors.Is(err, ErrDNSHistoryCapacity) {
		t.Fatalf("third target error = %v, want capacity error", err)
	}
	if err := s.AddDNSHistory(ctx, "one.example", map[string]string{"A": "203.0.113.2"}); err != nil {
		t.Fatalf("existing target update at capacity: %v", err)
	}
	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HistoryCount != 2 {
		t.Fatalf("history count = %d, want 2", stats.HistoryCount)
	}

	mr.FastForward(time.Hour + time.Second)
	stats, err = s.GetSystemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HistoryCount != 0 {
		t.Fatalf("expired history count = %d, want 0", stats.HistoryCount)
	}
	if err := s.AddDNSHistory(ctx, "three.example", map[string]string{"A": "203.0.113.3"}); err != nil {
		t.Fatalf("add after expiry: %v", err)
	}
}

func TestStorage_GetDNSHistoryReturnsEmptySlice(t *testing.T) {
	s := setupMiniredis(t)
	entries, err := s.GetDNSHistory(context.Background(), "missing.example")
	if err != nil {
		t.Fatal(err)
	}
	if entries == nil || len(entries) != 0 {
		t.Fatalf("entries = %#v, want non-nil empty slice", entries)
	}
}

func TestStorage_AddDNSHistoryRejectsUnencodableValueBeforeMutation(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	const target = "invalid-history.example"

	if err := s.AddDNSHistory(ctx, target, map[string]interface{}{"value": math.NaN()}); err == nil {
		t.Fatal("AddDNSHistory accepted an unencodable value")
	}
	history, err := s.GetDNSHistory(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Fatalf("history entries = %d, want 0 after rejected value", len(history))
	}
	tracked, err := s.Client.SCard(ctx, dnsHistoryTargetsKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if tracked != 0 {
		t.Fatalf("tracked targets = %d, want 0 after rejected value", tracked)
	}
}

func TestStorage_GetHistoryWithDiffsReturnsMalformedResultError(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	const target = "malformed-history.example"
	entries := []model.HistoryEntry{
		{Timestamp: "new", Result: "not-json"},
		{Timestamp: "old", Result: `{"A":["192.0.2.1"]}`},
	}
	for _, entry := range entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Client.RPush(ctx, "dns_history:"+target, encoded).Err(); err != nil {
			t.Fatal(err)
		}
	}

	if _, _, err := s.GetHistoryWithDiffs(ctx, target); err == nil {
		t.Fatal("GetHistoryWithDiffs accepted malformed result JSON")
	}
}

func TestStorage_DNSHistoryPersistsWhenTrackingFails(t *testing.T) {
	s := setupMiniredis(t)
	s.Client = &failingSAddClient{RedisClient: s.Client}
	ctx := context.Background()

	if err := s.AddDNSHistory(ctx, "example.com", map[string]string{"A": "192.0.2.1"}); err != nil {
		t.Fatalf("AddDNSHistory failed because tracking failed: %v", err)
	}
	history, err := s.GetDNSHistory(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetDNSHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history entries = %d, want 1", len(history))
	}
}

func TestStorage_DNSHistoryUnchangedEntryRepairsTracking(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	result := map[string]string{"A": "192.0.2.1"}
	if err := s.AddDNSHistory(ctx, "example.com", result); err != nil {
		t.Fatal(err)
	}
	if err := s.Client.Del(ctx, dnsHistoryTargetsKey).Err(); err != nil {
		t.Fatal(err)
	}

	if err := s.AddDNSHistory(ctx, "example.com", result); err != nil {
		t.Fatal(err)
	}
	count, err := s.Client.SCard(ctx, dnsHistoryTargetsKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("tracked targets = %d, want 1", count)
	}
}

func TestStorage_GetDNSHistory_UnmarshalError(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	target := "error.com"

	// Push invalid JSON
	_ = s.Client.RPush(ctx, "dns_history:"+target, "invalid-json").Err()

	entries, err := s.GetDNSHistory(ctx, target)
	if err != nil {
		t.Fatalf("GetDNSHistory failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries due to unmarshal error, got %d", len(entries))
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

func TestStorage_StatsBackfillsLegacyHistoryKeys(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	if err := s.Client.LPush(ctx, "dns_history:legacy.example", "legacy").Err(); err != nil {
		t.Fatal(err)
	}

	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}
	if stats.HistoryCount != 1 {
		t.Fatalf("HistoryCount = %d, want 1", stats.HistoryCount)
	}
	tracked, err := s.Client.SCard(ctx, dnsHistoryTargetsKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if tracked != 1 {
		t.Fatalf("backfilled targets = %d, want 1", tracked)
	}
}

func TestStorage_StatsMigratesMixedTrackedAndUntrackedHistory(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := &Storage{Client: client}
	s.ConfigureDNSHistory(10, time.Hour)
	ctx := context.Background()

	for _, target := range []string{"tracked.example", "untracked.example"} {
		if err := client.LPush(ctx, dnsHistoryKeyPrefix+target, "legacy").Err(); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SAdd(ctx, dnsHistoryTargetsKey, "tracked.example").Err(); err != nil {
		t.Fatal(err)
	}

	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HistoryCount != 2 {
		t.Fatalf("mixed legacy history count = %d, want 2", stats.HistoryCount)
	}
	for _, target := range []string{"tracked.example", "untracked.example"} {
		ttl, err := client.TTL(ctx, dnsHistoryKeyPrefix+target).Result()
		if err != nil {
			t.Fatal(err)
		}
		if ttl <= 0 || ttl > time.Hour {
			t.Fatalf("%s TTL = %s, want (0, 1h]", target, ttl)
		}
		tracked, err := client.SIsMember(ctx, dnsHistoryTargetsKey, target).Result()
		if err != nil {
			t.Fatal(err)
		}
		if !tracked {
			t.Fatalf("%s was not added to the tracking set", target)
		}
	}
}

func TestStorage_StatsLegacyMigrationIsBoundedAndResumable(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := &Storage{Client: client}
	s.ConfigureDNSHistory(1000, time.Hour)
	ctx := context.Background()
	const total = dnsHistoryMigrationBatch + 37

	for i := range total {
		target := fmt.Sprintf("legacy-%03d.example", i)
		if err := client.LPush(ctx, dnsHistoryKeyPrefix+target, "legacy").Err(); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HistoryCount <= 0 || stats.HistoryCount > dnsHistoryMigrationBatch {
		t.Fatalf("first migration processed %d targets, want 1..%d", stats.HistoryCount, dnsHistoryMigrationBatch)
	}

	for attempts := 0; stats.HistoryCount < total && attempts < 10; attempts++ {
		stats, err = s.GetSystemStats(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if stats.HistoryCount != total {
		t.Fatalf("resumed migration count = %d, want %d", stats.HistoryCount, total)
	}
	for i := range total {
		target := fmt.Sprintf("legacy-%03d.example", i)
		ttl, err := client.TTL(ctx, dnsHistoryKeyPrefix+target).Result()
		if err != nil {
			t.Fatal(err)
		}
		if ttl <= 0 {
			t.Fatalf("%s was not migrated to expiring retention", target)
		}
	}
}

func TestStorage_StatsStaleCleanupIsBoundedAndConverges(t *testing.T) {
	s := setupMiniredis(t)
	ctx := context.Background()
	const total = dnsHistoryMigrationBatch + 37
	members := make([]interface{}, 0, total)
	for i := range total {
		members = append(members, fmt.Sprintf("stale-%03d.example", i))
	}
	if err := s.Client.SAdd(ctx, dnsHistoryTargetsKey, members...).Err(); err != nil {
		t.Fatal(err)
	}

	stats, err := s.GetSystemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.HistoryCount < total-dnsHistoryMigrationBatch || stats.HistoryCount >= total {
		t.Fatalf("first bounded cleanup count = %d, want [%d, %d)", stats.HistoryCount, total-dnsHistoryMigrationBatch, total)
	}
	for attempts := 0; stats.HistoryCount > 0 && attempts < 10; attempts++ {
		stats, err = s.GetSystemStats(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if stats.HistoryCount != 0 {
		t.Fatalf("stale cleanup did not converge: count=%d", stats.HistoryCount)
	}
}

func TestNewStorage(t *testing.T) {
	s := NewStorage("localhost", "6379")
	if s.Client == nil {
		t.Error("Storage client should not be nil")
	}
}

func TestNormalizeData(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "Primitive string",
			input:    "hello",
			expected: "hello",
		},
		{
			name: "Map with empty/nil fields",
			input: map[string]interface{}{
				"keep":  "value",
				"nil":   nil,
				"empty": "",
				"slice": []interface{}{},
				"map":   map[string]interface{}{},
			},
			expected: map[string]interface{}{
				"keep": "value",
			},
		},
		{
			name:     "Empty map becomes nil",
			input:    map[string]interface{}{"empty": ""},
			expected: nil,
		},
		{
			name: "Slice with duplicates and nil",
			input: []interface{}{
				"b", "a", "b", nil, "c", "a",
			},
			expected: []interface{}{
				"a", "b", "c",
			},
		},
		{
			name:     "Empty slice becomes nil",
			input:    []interface{}{nil},
			expected: nil,
		},
		{
			name: "Nested normalization",
			input: map[string]interface{}{
				"nested": []interface{}{
					map[string]interface{}{"z": 1, "y": 2},
					map[string]interface{}{"y": 2, "z": 1},
				},
			},
			expected: map[string]interface{}{
				"nested": []interface{}{
					map[string]interface{}{"y": 2, "z": 1},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeData(tt.input)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(tt.expected)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("normalizeData() = %s, want %s", string(gotJSON), string(wantJSON))
			}
		})
	}
}
