package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"whois/internal/model"
	"whois/internal/utils"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	LRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd
	RPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LRem(ctx context.Context, key string, count int64, value interface{}) *redis.IntCmd
	LIndex(ctx context.Context, key string, index int64) *redis.StringCmd
	LPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd
	LTrim(ctx context.Context, key string, start, stop int64) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
	Pipeline() redis.Pipeliner
	Ping(ctx context.Context) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

type Storage struct {
	Client RedisClient
}

func NewStorage(host, port string) *Storage {
	rdb := redis.NewClient(&redis.Options{
		Addr: host + ":" + port,
		DB:   0,
	})
	return &Storage{Client: rdb}
}

func (s *Storage) GetMonitoredItems(ctx context.Context) ([]string, error) {
	res, err := s.Client.LRange(ctx, "monitored_items", 0, -1).Result()
	if err == nil {
		utils.Log.Debug("redis lrange", utils.Field("key", "monitored_items"), utils.Field("count", len(res)))
	}
	return res, err
}

func (s *Storage) AddMonitoredItem(ctx context.Context, item string) error {
	utils.Log.Info("redis rpush", utils.Field("key", "monitored_items"), utils.Field("item", item))
	return s.Client.RPush(ctx, "monitored_items", item).Err()
}

func (s *Storage) RemoveMonitoredItem(ctx context.Context, item string) error {
	utils.Log.Info("redis lrem", utils.Field("key", "monitored_items"), utils.Field("item", item))
	return s.Client.LRem(ctx, "monitored_items", 0, item).Err()
}

func (s *Storage) GetDNSHistory(ctx context.Context, item string) ([]model.HistoryEntry, error) {
	historyKey := "dns_history:" + item
	val, err := s.Client.LRange(ctx, historyKey, 0, -1).Result()
	if err != nil {
		utils.Log.Error("failed to fetch history from redis", utils.Field("key", historyKey), utils.Field("error", err))
		return nil, err
	}
	utils.Log.Debug("redis lrange", utils.Field("key", historyKey), utils.Field("count", len(val)))
	var entries []model.HistoryEntry
	for _, v := range val {
		var entry model.HistoryEntry
		if err := json.Unmarshal([]byte(v), &entry); err != nil {
			utils.Log.Warn("failed to unmarshal history entry", utils.Field("key", historyKey), utils.Field("error", err))
			continue
		}
		entries = append(entries, entry)
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

		// Normalize to reduce noise from reordered arrays
		currentObj = normalizeData(currentObj)
		previousObj = normalizeData(previousObj)

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
	// Normalize input data before saving to ensure consistent comparison
	// Marshal and Unmarshal to ensure we have a generic interface{} structure to normalize
	resBytes, _ := json.Marshal(result)
	var obj interface{}
	_ = json.Unmarshal(resBytes, &obj)
	normalizedObj := normalizeData(obj)
	resBytes, _ = json.Marshal(normalizedObj)
	resStr := string(resBytes)

	// Fetch metadata or versioning info if needed
	historyKey := "dns_history:" + item

	lastEntryJSON, err := s.Client.LIndex(ctx, historyKey, 0).Result()
	if err == nil {
		var lastEntry model.HistoryEntry
		if json.Unmarshal([]byte(lastEntryJSON), &lastEntry) == nil {
			if lastEntry.Result == resStr {
				utils.Log.Debug("redis history unchanged", utils.Field("item", item))
				return nil
			}
		}
	}

	entry := model.HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    resStr,
	}
	entryBytes, _ := json.Marshal(entry)

	utils.Log.Info("redis history update", utils.Field("item", item))
	pipe := s.Client.Pipeline()
	pipe.LPush(ctx, historyKey, string(entryBytes))
	pipe.LTrim(ctx, historyKey, 0, 99)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Storage) GetCache(ctx context.Context, key string) (string, error) {
	res, err := s.Client.Get(ctx, key).Result()
	if err == nil {
		utils.Log.Debug("redis cache hit", utils.Field("key", key))
	} else if err != redis.Nil {
		utils.Log.Warn("redis cache error", utils.Field("key", key), utils.Field("error", err.Error()))
	}
	return res, err
}

func (s *Storage) SetCache(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	val, _ := json.Marshal(value)
	utils.Log.Debug("redis cache set", utils.Field("key", key), utils.Field("exp", expiration.String()))
	return s.Client.Set(ctx, key, val, expiration).Err()
}

type SystemStats struct {
	MonitoredCount int `json:"monitored_count"`
	HistoryCount   int `json:"history_count"`
}

func (s *Storage) GetSystemStats(ctx context.Context) (SystemStats, error) {
	monitored, _ := s.GetMonitoredItems(ctx)

	// Count total history entries using SCAN for performance
	count := 0
	iter := s.Client.Scan(ctx, 0, "dns_history:*", 0).Iterator()
	for iter.Next(ctx) {
		count++
	}

	utils.Log.Debug("redis stats gathered", utils.Field("monitored", len(monitored)), utils.Field("history", count))
	return SystemStats{
		MonitoredCount: len(monitored),
		HistoryCount:   count,
	}, nil
}

// normalizeData recursively sorts and deduplicates slices, and removes empty fields
func normalizeData(i interface{}) interface{} {
	switch v := i.(type) {
	case map[string]interface{}:
		cleaned := make(map[string]interface{})
		for k, val := range v {
			normVal := normalizeData(val)
			// Remove empty/nil values to reduce noise from flaky lookups
			if normVal == nil {
				continue
			}
			if s, ok := normVal.(string); ok && s == "" {
				continue
			}
			if sl, ok := normVal.([]interface{}); ok && len(sl) == 0 {
				continue
			}
			if m, ok := normVal.(map[string]interface{}); ok && len(m) == 0 {
				continue
			}
			cleaned[k] = normVal
		}
		if len(cleaned) == 0 {
			return nil
		}
		return cleaned
	case []interface{}:
		if len(v) == 0 {
			return nil
		}
		
		// Recurse first
		for idx, val := range v {
			v[idx] = normalizeData(val)
		}

		// Deduplicate
		uniqueMap := make(map[string]interface{})
		var uniqueSlice []interface{}
		for _, val := range v {
			if val == nil {
				continue
			}
			key := fmt.Sprintf("%v", val)
			if _, exists := uniqueMap[key]; !exists {
				uniqueMap[key] = val
				uniqueSlice = append(uniqueSlice, val)
			}
		}

		// Sort
		sort.Slice(uniqueSlice, func(i, j int) bool {
			return fmt.Sprintf("%v", uniqueSlice[i]) < fmt.Sprintf("%v", uniqueSlice[j])
		})
		
		if len(uniqueSlice) == 0 {
			return nil
		}
		return uniqueSlice
	default:
		return i
	}
}
