package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"whois/internal/model"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/redis/go-redis/v9"
)

type Storage struct {
	Client *redis.Client
}

func NewStorage(host, port string) *Storage {
	rdb := redis.NewClient(&redis.Options{
		Addr: host + ":" + port,
		DB:   0,
	})
	return &Storage{Client: rdb}
}

func (s *Storage) GetMonitoredItems(ctx context.Context) ([]string, error) {
	return s.Client.LRange(ctx, "monitored_items", 0, -1).Result()
}

func (s *Storage) AddMonitoredItem(ctx context.Context, item string) error {
	return s.Client.RPush(ctx, "monitored_items", item).Err()
}

func (s *Storage) RemoveMonitoredItem(ctx context.Context, item string) error {
	return s.Client.LRem(ctx, "monitored_items", 0, item).Err()
}

func (s *Storage) GetDNSHistory(ctx context.Context, item string) ([]model.HistoryEntry, error) {
	val, err := s.Client.LRange(ctx, "dns_history:"+item, 0, -1).Result()
	if err != nil {
		return nil, err
	}
	var entries []model.HistoryEntry
	for _, v := range val {
		var entry model.HistoryEntry
		if err := json.Unmarshal([]byte(v), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (s *Storage) GetHistoryWithDiffs(ctx context.Context, item string) ([]model.HistoryEntry, []string, error) {
	entries, err := s.GetDNSHistory(ctx, item)
	if err != nil {
		return nil, nil, err
	}

	diffs := make([]string, 0)
	if len(entries) < 2 {
		return entries, diffs, nil
	}

	for i := 0; i < len(entries)-1; i++ {
		currentRaw := entries[i].Result
		previousRaw := entries[i+1].Result

		// Pretty print JSON for better diff
		var currentObj, previousObj interface{}
		_ = json.Unmarshal([]byte(currentRaw), &currentObj)
		_ = json.Unmarshal([]byte(previousRaw), &previousObj)

		currentPretty, _ := json.MarshalIndent(currentObj, "", "  ")
		previousPretty, _ := json.MarshalIndent(previousObj, "", "  ")

		edits := myers.ComputeEdits(span.URIFromPath("previous"), string(previousPretty), string(currentPretty))
		diff := fmt.Sprint(gotextdiff.ToUnified("previous", "current", string(previousPretty), edits))

		if diff == "" {
			diffs = append(diffs, "No changes")
		} else {
			diffs = append(diffs, diff)
		}
	}

	return entries, diffs, nil
}

type HistoryMetadata struct {
	RecordCount int `json:"record_count"`
	Version     int `json:"version"`
}

func (s *Storage) AddDNSHistory(ctx context.Context, item string, result interface{}) error {
	resBytes, _ := json.Marshal(result)
	resStr := string(resBytes)

	// Fetch metadata or versioning info if needed
	historyKey := "dns_history:" + item

	lastEntryJSON, err := s.Client.LIndex(ctx, historyKey, 0).Result()
	if err == nil {
		var lastEntry model.HistoryEntry
		if json.Unmarshal([]byte(lastEntryJSON), &lastEntry) == nil {
			if lastEntry.Result == resStr {
				return nil
			}
		}
	}

	entry := model.HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    resStr,
	}
	entryBytes, _ := json.Marshal(entry)

	pipe := s.Client.Pipeline()
	pipe.LPush(ctx, historyKey, string(entryBytes))
	pipe.LTrim(ctx, historyKey, 0, 99)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Storage) GetCache(ctx context.Context, key string) (string, error) {
	return s.Client.Get(ctx, key).Result()
}

func (s *Storage) SetCache(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	val, _ := json.Marshal(value)
	return s.Client.Set(ctx, key, val, expiration).Err()
}

type SystemStats struct {
	MonitoredCount int `json:"monitored_count"`
	HistoryCount   int `json:"history_count"`
}

func (s *Storage) GetSystemStats(ctx context.Context) (SystemStats, error) {
	monitored, _ := s.GetMonitoredItems(ctx)

	// Count total history entries (simplified logic)
	keys, _ := s.Client.Keys(ctx, "dns_history:*").Result()

	return SystemStats{
		MonitoredCount: len(monitored),
		HistoryCount:   len(keys),
	}, nil
}
