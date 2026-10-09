package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"whois/internal/model"
	"whois/internal/utils"
)

const (
	routingEndpoint   = "https://stat.ripe.net/data/network-info/data.json"
	routingTimeout    = 3 * time.Second
	routingCacheTTL   = time.Hour
	routingCacheLimit = 512
	routingBodyLimit  = 128 << 10
)

// The limit applies across service instances in this process.
var routingRequestSlots = make(chan struct{}, 4)

type routingCacheEntry struct {
	result  model.RoutingInfo
	expires time.Time
}

// RoutingService uses fixed RIPEstat endpoints and never resolves a
// user-supplied hostname or follows provider redirects.
type RoutingService struct {
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]routingCacheEntry
}

func NewRoutingService() *RoutingService {
	return &RoutingService{
		client: &http.Client{
			Timeout: routingTimeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: routingTimeout, KeepAlive: 30 * time.Second}).DialContext,
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       time.Minute,
				TLSHandshakeTimeout:   routingTimeout,
				ResponseHeaderTimeout: routingTimeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   time.Now,
		cache: make(map[string]routingCacheEntry),
	}
}

func (s *RoutingService) Lookup(ctx context.Context, target string) (result model.RoutingInfo) {
	query := strings.TrimSpace(target)
	if len(query) >= 2 && strings.EqualFold(query[:2], "AS") && !strings.ContainsAny(query, ".:/") {
		return s.lookupASN(ctx, query)
	}
	result = model.RoutingInfo{
		Query: query, Status: "skipped", Source: "RIPEstat / RIPE RIS", SnapshotCadenceHours: 8,
		Reason: "Routing lookup requires a public literal IP address or AS<number>; domains and CIDRs are not queried.",
	}
	ip, err := netip.ParseAddr(result.Query)
	if err != nil || ip.Zone() != "" {
		return result
	}
	ip = ip.Unmap()
	result.IP = ip.String()
	info := utils.NormalizeTarget(result.IP)
	if !info.Valid || len(info.IPs) != 1 || info.IPs[0].IsBogon {
		result.Reason = "Routing lookup is limited to public IP addresses; special-use addresses are not sent to the provider."
		return result
	}
	result.Status, result.Reason = "error", ""
	result.SourceURL = routingEndpoint + "?resource=" + url.QueryEscape(result.IP)
	ctx, cancel := context.WithTimeout(ctx, routingTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		return result
	}
	if cached, ok := s.cached(ip.String()); ok {
		cached.Query = result.Query
		return cached
	}
	select {
	case routingRequestSlots <- struct{}{}:
		defer func() { <-routingRequestSlots }()
	case <-ctx.Done():
		result.Error = ctx.Err().Error()
		return result
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		return result
	}
	if cached, ok := s.cached(ip.String()); ok {
		cached.Query = result.Query
		return cached
	}
	prefix, asns, err := s.fetch(ctx, result.SourceURL, ip)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	fetched := s.now().UTC()
	result.FetchedAt, result.Prefix, result.OriginASNs = &fetched, prefix, asns
	result.Status = "answer"
	if prefix == "" {
		result.Status = "no_announcement"
	}
	s.store(ip.String(), result)
	return result
}

func (s *RoutingService) fetchRoutingData(ctx context.Context, endpoint string, limit int64) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare routing request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("RIPEstat routing lookup failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat routing lookup returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read RIPEstat routing response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("RIPEstat routing response exceeds %d bytes", limit)
	}
	var envelope struct {
		Status     string          `json:"status"`
		StatusCode int             `json:"status_code"`
		Data       json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid RIPEstat routing response: %w", err)
	}
	if envelope.Status != "ok" || envelope.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat did not return a successful routing response")
	}
	if len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) {
		return nil, fmt.Errorf("RIPEstat routing response is missing data")
	}
	return envelope.Data, nil
}

func (s *RoutingService) fetch(ctx context.Context, endpoint string, ip netip.Addr) (string, []uint32, error) {
	body, err := s.fetchRoutingData(ctx, endpoint, routingBodyLimit)
	if err != nil {
		return "", nil, err
	}
	var data struct {
		Prefix json.RawMessage `json:"prefix"`
		ASNs   json.RawMessage `json:"asns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil, fmt.Errorf("invalid RIPEstat network data: %w", err)
	}
	if len(data.Prefix) == 0 || len(data.ASNs) == 0 || bytes.Equal(data.ASNs, []byte("null")) {
		return "", nil, fmt.Errorf("RIPEstat routing response is missing prefix or origin data")
	}
	var prefix string
	var rawASNs []json.RawMessage
	if err := json.Unmarshal(data.Prefix, &prefix); err != nil {
		return "", nil, fmt.Errorf("invalid RIPEstat routing prefix: %w", err)
	}
	if err := json.Unmarshal(data.ASNs, &rawASNs); err != nil {
		return "", nil, fmt.Errorf("invalid RIPEstat routing origins: %w", err)
	}
	if prefix == "" && len(rawASNs) == 0 {
		return "", nil, nil
	}
	network, err := netip.ParsePrefix(prefix)
	if err != nil || network.Addr().Is4() != ip.Is4() || !network.Contains(ip) || len(rawASNs) == 0 {
		return "", nil, fmt.Errorf("RIPEstat routing prefix or origins do not match the requested IP")
	}
	asns := make([]uint32, 0, len(rawASNs))
	for _, raw := range rawASNs {
		value := string(raw)
		if len(raw) > 0 && raw[0] == '"' {
			if err := json.Unmarshal(raw, &value); err != nil {
				return "", nil, fmt.Errorf("invalid RIPEstat origin ASN: %w", err)
			}
		}
		asn, err := strconv.ParseUint(value, 10, 32)
		if err != nil || asn == 0 {
			return "", nil, fmt.Errorf("RIPEstat origin ASN must be a positive 32-bit integer")
		}
		asns = append(asns, uint32(asn))
	}
	slices.Sort(asns)
	return network.Masked().String(), slices.Compact(asns), nil
}

func (s *RoutingService) cached(key string) (model.RoutingInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || !s.now().Before(entry.expires) {
		delete(s.cache, key)
		return model.RoutingInfo{}, false
	}
	return cloneRoutingInfo(entry.result), true
}

func (s *RoutingService) store(key string, result model.RoutingInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var oldest string
	var earliest time.Time
	var oldestASN string
	var earliestASN time.Time
	asnEntries := 0
	for key, entry := range s.cache {
		if !now.Before(entry.expires) {
			delete(s.cache, key)
			continue
		}
		if oldest == "" || entry.expires.Before(earliest) {
			oldest, earliest = key, entry.expires
		}
		if entry.result.ASN != nil {
			asnEntries++
			if oldestASN == "" || entry.expires.Before(earliestASN) {
				oldestASN, earliestASN = key, entry.expires
			}
		}
	}
	if _, exists := s.cache[key]; !exists && result.ASN != nil && asnEntries >= asnCacheLimit {
		delete(s.cache, oldestASN)
	}
	if _, exists := s.cache[key]; !exists && len(s.cache) >= routingCacheLimit {
		delete(s.cache, oldest)
	}
	s.cache[key] = routingCacheEntry{result: cloneRoutingInfo(result), expires: result.FetchedAt.Add(routingCacheTTL)}
}

func cloneRoutingInfo(result model.RoutingInfo) model.RoutingInfo {
	result.OriginASNs = slices.Clone(result.OriginASNs)
	result.ASN = cloneASNInfo(result.ASN)
	if result.FetchedAt != nil {
		fetched := *result.FetchedAt
		result.FetchedAt = &fetched
	}
	return result
}

// RoutingCacheTTL prevents an aggregate query cache from extending provider data
// past the service cache lifetime or retaining an upstream failure.
func RoutingCacheTTL(result *model.RoutingInfo, now time.Time, maximum time.Duration) time.Duration {
	if result == nil || maximum <= 0 {
		return 0
	}
	if result.Status == "skipped" {
		return maximum
	}
	if result.ASN != nil && (result.ASN.Prefixes == nil || result.ASN.Prefixes.Status != "answer") {
		return 0
	}
	if (result.Status != "answer" && result.Status != "no_announcement") || result.FetchedAt == nil || result.FetchedAt.After(now) {
		return 0
	}
	return max(0, min(maximum, result.FetchedAt.Add(routingCacheTTL).Sub(now)))
}
