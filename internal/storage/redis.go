package storage

import (
	"context"
	"encoding/json"
	"time"
	"whois/internal/model"

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

func (s *Storage) AddDNSHistory(ctx context.Context, item string, result interface{}) error {
	// Match Python's logic: Check latest entry to avoid duplicates
	// Serialize result to JSON string
	resBytes, _ := json.Marshal(result)
	resStr := string(resBytes)

	// Check last entry
	lastEntryJSON, err := s.Client.LIndex(ctx, "dns_history:"+item, 0).Result()
	if err == nil {
		var lastEntry model.HistoryEntry
		if json.Unmarshal([]byte(lastEntryJSON), &lastEntry) == nil {
			// In python it compares json dumps.
			// Here we compare the result string field.
			if lastEntry.Result == resStr {
				return nil // No change
			}
		}
	}

	entry := model.HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339) + "Z", // Match Python isoformat() + 'Z' rough approx
		Result:    resStr,
	}
	entryBytes, _ := json.Marshal(entry)
	
	pipe := s.Client.Pipeline()
	pipe.LPush(ctx, "dns_history:"+item, string(entryBytes))
	pipe.LTrim(ctx, "dns_history:"+item, 0, 99)
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
