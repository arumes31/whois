package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
	SCard(ctx context.Context, key string) *redis.IntCmd
}

type Storage struct {
	Client               RedisClient
	DNSHistoryMaxTargets int
	DNSHistoryTTL        time.Duration

	historyMigrationMu      sync.Mutex
	historyMigrationCursor  uint64
	historyMigrationPending []string
	historyMigrationDone    bool
	historyCleanupCursor    uint64
}

const (
	dnsHistoryTargetsKey        = "dns_history_targets"
	defaultDNSHistoryMaxTargets = 1000
	defaultDNSHistoryTTL        = 30 * 24 * time.Hour
	dnsHistoryKeyPrefix         = "dns_history:"
	dnsHistoryMigrationBatch    = 100
	dnsHistoryMigrationMaxScans = 4
)

// ErrDNSHistoryCapacity indicates that a new target would exceed retention policy.
var ErrDNSHistoryCapacity = errors.New("dns history target capacity reached")

const addMonitoredItemIfAbsentScript = `
local items = redis.call("LRANGE", KEYS[1], 0, -1)
for _, existing in ipairs(items) do
    if existing == ARGV[1] then
        return 0
    end
end
redis.call("RPUSH", KEYS[1], ARGV[1])
return 1
`

const writeDNSHistoryScript = `
local targets_key = KEYS[1]
local history_key = KEYS[2]
local target = ARGV[1]
local max_targets = tonumber(ARGV[2])
local history_prefix = ARGV[3]
local ttl_seconds = tonumber(ARGV[4])
local entry = ARGV[5]
local normalized_result = ARGV[6]

if redis.call("SISMEMBER", targets_key, target) == 0 then
    if redis.call("SCARD", targets_key) >= max_targets then
        local members = redis.call("SMEMBERS", targets_key)
        for _, member in ipairs(members) do
            if redis.call("EXISTS", history_prefix .. member) == 0 then
                redis.call("SREM", targets_key, member)
            end
        end
        if redis.call("SCARD", targets_key) >= max_targets then
            return -1
        end
    end
    redis.call("SADD", targets_key, target)
end

local write_entry = true
local current = redis.call("LINDEX", history_key, 0)
if current then
    local decoded_ok, decoded = pcall(cjson.decode, current)
    if decoded_ok and type(decoded) == "table" and decoded["result"] == normalized_result then
        write_entry = false
    end
end

if write_entry then
    redis.call("LPUSH", history_key, entry)
    redis.call("LTRIM", history_key, 0, 99)
end
redis.call("EXPIRE", history_key, ttl_seconds)
if write_entry then
    return 1
end
return 0
`

const countLiveDNSHistoryTargetsScript = `
local scan = redis.call("SSCAN", KEYS[1], ARGV[2], "COUNT", ARGV[3])
local members = scan[2]
for _, member in ipairs(members) do
    if redis.call("EXISTS", ARGV[1] .. member) == 0 then
        redis.call("SREM", KEYS[1], member)
    end
end
return scan[1] .. ":" .. redis.call("SCARD", KEYS[1])
`

func NewStorage(host, port string) *Storage {
	rdb := redis.NewClient(&redis.Options{
		Addr: net.JoinHostPort(host, port),
		DB:   0,
	})
	return &Storage{
		Client:               rdb,
		DNSHistoryMaxTargets: defaultDNSHistoryMaxTargets,
		DNSHistoryTTL:        defaultDNSHistoryTTL,
	}
}

func (s *Storage) ConfigureDNSHistory(maxTargets int, ttl time.Duration) {
	if maxTargets > 0 {
		s.DNSHistoryMaxTargets = maxTargets
	}
	if ttl > 0 {
		s.DNSHistoryTTL = ttl
	}
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

// AddMonitoredItemIfAbsent atomically appends item when it is not already in
// the monitored list. The Redis-side check prevents duplicates across server
// instances handling concurrent requests.
func (s *Storage) AddMonitoredItemIfAbsent(ctx context.Context, item string) (bool, error) {
	result, err := s.Client.Eval(ctx, addMonitoredItemIfAbsentScript, []string{"monitored_items"}, item).Int()
	if err != nil {
		return false, err
	}
	if result == 1 {
		utils.Log.Info("redis rpush", utils.Field("key", "monitored_items"), utils.Field("item", item))
	}
	return result == 1, nil
}

func (s *Storage) RemoveMonitoredItem(ctx context.Context, item string) error {
	utils.Log.Info("redis lrem", utils.Field("key", "monitored_items"), utils.Field("item", item))
	return s.Client.LRem(ctx, "monitored_items", 0, item).Err()
}

func (s *Storage) GetDNSHistory(ctx context.Context, item string) ([]model.HistoryEntry, error) {
	historyKey := dnsHistoryKeyPrefix + item
	val, err := s.Client.LRange(ctx, historyKey, 0, -1).Result()
	if err != nil {
		utils.Log.Error("failed to fetch history from redis", utils.Field("key", historyKey), utils.Field("error", err))
		return nil, err
	}
	utils.Log.Debug("redis lrange", utils.Field("key", historyKey), utils.Field("count", len(val)))
	entries := make([]model.HistoryEntry, 0, len(val))
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
		if err := json.Unmarshal([]byte(currentRaw), &currentObj); err != nil {
			return nil, nil, fmt.Errorf("decode current DNS history result: %w", err)
		}
		if err := json.Unmarshal([]byte(previousRaw), &previousObj); err != nil {
			return nil, nil, fmt.Errorf("decode previous DNS history result: %w", err)
		}

		// Normalize to reduce noise from reordered arrays
		currentObj = normalizeData(currentObj)
		previousObj = normalizeData(previousObj)

		currentPretty, err := json.MarshalIndent(currentObj, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("encode current DNS history result: %w", err)
		}
		previousPretty, err := json.MarshalIndent(previousObj, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("encode previous DNS history result: %w", err)
		}

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
	resBytes, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode DNS history result: %w", err)
	}
	var obj interface{}
	if err := json.Unmarshal(resBytes, &obj); err != nil {
		return fmt.Errorf("normalize DNS history result: %w", err)
	}
	normalizedObj := normalizeData(obj)
	resBytes, err = json.Marshal(normalizedObj)
	if err != nil {
		return fmt.Errorf("encode normalized DNS history result: %w", err)
	}
	resStr := string(resBytes)

	entry := model.HistoryEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    resStr,
	}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode DNS history entry: %w", err)
	}

	utils.Log.Info("redis history update", utils.Field("item", item))
	return s.writeDNSHistory(ctx, item, string(entryBytes), resStr)
}

func (s *Storage) writeDNSHistory(ctx context.Context, item, entry, normalizedResult string) error {
	maxTargets := s.DNSHistoryMaxTargets
	if maxTargets < 1 {
		maxTargets = defaultDNSHistoryMaxTargets
	}
	ttl := s.DNSHistoryTTL
	if ttl <= 0 {
		ttl = defaultDNSHistoryTTL
	}
	result, err := s.Client.Eval(
		ctx,
		writeDNSHistoryScript,
		[]string{dnsHistoryTargetsKey, dnsHistoryKeyPrefix + item},
		item,
		maxTargets,
		dnsHistoryKeyPrefix,
		int64(ttl/time.Second),
		entry,
		normalizedResult,
	).Int()
	if err != nil {
		return fmt.Errorf("write DNS history: %w", err)
	}
	if result == -1 {
		return ErrDNSHistoryCapacity
	}
	return nil
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
	val, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode cache value: %w", err)
	}
	utils.Log.Debug("redis cache set", utils.Field("key", key), utils.Field("exp", expiration.String()))
	return s.Client.Set(ctx, key, val, expiration).Err()
}

type SystemStats struct {
	MonitoredCount int `json:"monitored_count"`
	HistoryCount   int `json:"history_count"`
}

func (s *Storage) GetSystemStats(ctx context.Context) (SystemStats, error) {
	monitored, err := s.GetMonitoredItems(ctx)
	if err != nil {
		return SystemStats{}, fmt.Errorf("read monitored items: %w", err)
	}
	if err := s.migrateDNSHistoryRetention(ctx); err != nil {
		return SystemStats{}, err
	}
	historyCount, err := s.countLiveDNSHistoryTargets(ctx)
	if err != nil {
		return SystemStats{}, fmt.Errorf("count DNS history targets: %w", err)
	}

	utils.Log.Debug("redis stats gathered", utils.Field("monitored", len(monitored)), utils.Field("history", historyCount))
	return SystemStats{
		MonitoredCount: len(monitored),
		HistoryCount:   int(historyCount),
	}, nil
}

// countLiveDNSHistoryTargets removes at most one bounded SSCAN batch of stale
// members before returning SCARD. Counts can temporarily include unvisited
// expired members, but each stats request advances the cursor and normal writes
// perform a full stale sweep only when capacity would otherwise be exceeded.
func (s *Storage) countLiveDNSHistoryTargets(ctx context.Context) (int64, error) {
	s.historyMigrationMu.Lock()
	defer s.historyMigrationMu.Unlock()

	value, err := s.Client.Eval(
		ctx,
		countLiveDNSHistoryTargetsScript,
		[]string{dnsHistoryTargetsKey},
		dnsHistoryKeyPrefix,
		s.historyCleanupCursor,
		dnsHistoryMigrationBatch,
	).Text()
	if err != nil {
		return 0, err
	}
	cursorText, countText, ok := strings.Cut(value, ":")
	if !ok {
		return 0, fmt.Errorf("unexpected history count response")
	}
	cursor, err := strconv.ParseUint(cursorText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode history cleanup cursor: %w", err)
	}
	count, err := strconv.ParseInt(countText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode history target count: %w", err)
	}
	s.historyCleanupCursor = cursor
	return count, nil
}

// migrateDNSHistoryRetention incrementally discovers legacy history keys,
// registers untracked targets, and adds the configured TTL. Work and memory are
// capped per call so a large pre-policy keyspace cannot stall a stats request.
// Cursor state is committed only after the idempotent Redis pipeline succeeds,
// allowing a failed batch to be retried safely on the next request.
func (s *Storage) migrateDNSHistoryRetention(ctx context.Context) error {
	s.historyMigrationMu.Lock()
	defer s.historyMigrationMu.Unlock()

	if s.historyMigrationDone {
		return nil
	}

	cursor := s.historyMigrationCursor
	pending := append([]string(nil), s.historyMigrationPending...)
	done := false
	scanCalls := 0
	targets := make([]string, 0, dnsHistoryMigrationBatch)

	for len(targets) < dnsHistoryMigrationBatch && !done {
		if len(pending) == 0 {
			if scanCalls >= dnsHistoryMigrationMaxScans {
				break
			}
			keys, nextCursor, err := s.Client.Scan(ctx, cursor, dnsHistoryKeyPrefix+"*", dnsHistoryMigrationBatch).Result()
			if err != nil {
				return fmt.Errorf("scan DNS history targets: %w", err)
			}
			scanCalls++
			cursor = nextCursor
			pending = keys
			if len(pending) == 0 {
				if cursor == 0 {
					done = true
				}
				continue
			}
		}

		remaining := dnsHistoryMigrationBatch - len(targets)
		take := min(remaining, len(pending))
		for _, key := range pending[:take] {
			if !strings.HasPrefix(key, dnsHistoryKeyPrefix) {
				continue
			}
			target := strings.TrimPrefix(key, dnsHistoryKeyPrefix)
			if target != "" {
				targets = append(targets, target)
			}
		}
		pending = pending[take:]
		if len(pending) == 0 && cursor == 0 {
			done = true
		}
	}

	if len(targets) > 0 {
		ttl := s.DNSHistoryTTL
		if ttl <= 0 {
			ttl = defaultDNSHistoryTTL
		}
		members := make([]interface{}, 0, len(targets))
		pipe := s.Client.Pipeline()
		for _, target := range targets {
			members = append(members, target)
			pipe.Expire(ctx, dnsHistoryKeyPrefix+target, ttl)
		}
		pipe.SAdd(ctx, dnsHistoryTargetsKey, members...)
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("migrate DNS history retention: %w", err)
		}
	}

	s.historyMigrationCursor = cursor
	s.historyMigrationPending = append(s.historyMigrationPending[:0], pending...)
	s.historyMigrationDone = done
	return nil
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
