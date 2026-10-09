package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"whois/internal/model"
)

const (
	asnOverviewEndpoint = "https://stat.ripe.net/data/as-overview/data.json"
	asnPrefixesEndpoint = "https://stat.ripe.net/data/announced-prefixes/data.json"
	asnPrefixesLimit    = 2 << 20
	asnCacheLimit       = 32
	asnMinPeersSeeing   = 10
)

func (s *RoutingService) lookupASN(ctx context.Context, query string) model.RoutingInfo {
	result := model.RoutingInfo{Query: query, Status: "error", Source: "RIPEstat / RIPE RIS"}
	number, err := parseASNNumber(query[2:])
	if err != nil {
		result.Error = err.Error()
		return result
	}
	resource := "AS" + strconv.FormatUint(uint64(number), 10)
	result.SourceURL = asnOverviewEndpoint + "?resource=" + resource
	ctx, cancel := context.WithTimeout(ctx, routingTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		return result
	}
	if cached, ok := s.cached(resource); ok {
		cached.Query = query
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
	if cached, ok := s.cached(resource); ok {
		cached.Query = query
		return cached
	}
	overview, err := s.fetchASNOverview(ctx, result.SourceURL, number)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	fetched := s.now().UTC()
	result.Status, result.FetchedAt, result.ASN = "answer", &fetched, overview
	// RIPEstat's default is two weeks. Request one explicit 24-hour window and
	// retain the returned available period rather than presenting it as current.
	end := fetched.Truncate(time.Second)
	start := end.Add(-24 * time.Hour)
	values := url.Values{
		"resource": {resource}, "starttime": {strconv.FormatInt(start.Unix(), 10)},
		"endtime": {strconv.FormatInt(end.Unix(), 10)}, "min_peers_seeing": {strconv.Itoa(asnMinPeersSeeing)},
	}
	endpoint := asnPrefixesEndpoint + "?" + values.Encode()
	prefixes, err := s.fetchASNPrefixes(ctx, endpoint, number, start, end)
	if err != nil {
		// The overview remains useful evidence even if the second request fails.
		overview.Prefixes = &model.ASNPrefixes{Status: "error", Items: []string{}, SourceURL: endpoint, Error: err.Error()}
		return result
	}
	overview.Prefixes = prefixes
	s.store(resource, result)
	return result
}

func (s *RoutingService) fetchASNOverview(ctx context.Context, endpoint string, number uint32) (*model.ASNInfo, error) {
	body, err := s.fetchRoutingData(ctx, endpoint, routingBodyLimit)
	if err != nil {
		return nil, err
	}
	var data struct {
		Resource  json.RawMessage `json:"resource"`
		Type      string          `json:"type"`
		Holder    string          `json:"holder"`
		Announced *bool           `json:"announced"`
		Start     string          `json:"query_starttime"`
		End       string          `json:"query_endtime"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("invalid RIPEstat ASN overview: %w", err)
	}
	if !matchingASNResource(data.Resource, number) || data.Type != "as" || data.Announced == nil {
		return nil, fmt.Errorf("RIPEstat overview does not contain the requested ASN and announcement observation")
	}
	start, end, err := parseRISPeriod(data.Start, data.End)
	if err != nil {
		return nil, err
	}
	return &model.ASNInfo{
		Number: number, Holder: data.Holder, Announced: data.Announced, MinPeersSeeing: asnMinPeersSeeing,
		OverviewStart: &start, OverviewEnd: &end,
	}, nil
}

func (s *RoutingService) fetchASNPrefixes(ctx context.Context, endpoint string, number uint32, requestedStart, requestedEnd time.Time) (*model.ASNPrefixes, error) {
	body, err := s.fetchRoutingData(ctx, endpoint, asnPrefixesLimit)
	if err != nil {
		return nil, err
	}
	var data struct {
		Resource json.RawMessage `json:"resource"`
		Start    string          `json:"query_starttime"`
		End      string          `json:"query_endtime"`
		Prefixes []struct {
			Prefix    string `json:"prefix"`
			Timelines []struct {
				Start string `json:"starttime"`
				End   string `json:"endtime"`
			} `json:"timelines"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("invalid RIPEstat ASN prefix data: %w", err)
	}
	if !matchingASNResource(data.Resource, number) || data.Prefixes == nil {
		return nil, fmt.Errorf("RIPEstat prefix response does not contain the requested ASN and prefix list")
	}
	start, end, err := parseRISPeriod(data.Start, data.End)
	if err != nil || start.Before(requestedStart) || end.After(requestedEnd) {
		return nil, fmt.Errorf("RIPEstat prefix observation period does not match the requested 24-hour window")
	}
	items := make([]string, 0, len(data.Prefixes))
	for _, item := range data.Prefixes {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || len(item.Timelines) == 0 {
			return nil, fmt.Errorf("RIPEstat returned an invalid announced prefix or missing timeline")
		}
		for _, timeline := range item.Timelines {
			first, last, err := parseRISPeriod(timeline.Start, timeline.End)
			if err != nil || first.After(end) || last.Before(start) {
				return nil, fmt.Errorf("RIPEstat prefix timeline does not overlap the reported observation period")
			}
		}
		items = append(items, prefix.String())
	}
	slices.Sort(items)
	fetched := s.now().UTC()
	return &model.ASNPrefixes{
		Status: "answer", Items: slices.Compact(items), PeriodStart: &start, PeriodEnd: &end,
		SourceURL: endpoint, FetchedAt: &fetched,
	}, nil
}

func parseASNNumber(value string) (uint32, error) {
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("ASN must be a positive 32-bit decimal number")
		}
	}
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || number == 0 {
		return 0, fmt.Errorf("ASN must be a positive 32-bit decimal number")
	}
	return uint32(number), nil
}

func matchingASNResource(raw json.RawMessage, expected uint32) bool {
	value := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return false
		}
	}
	if len(value) >= 2 && strings.EqualFold(value[:2], "AS") {
		value = value[2:]
	}
	number, err := parseASNNumber(value)
	return err == nil && number == expected
}

func parseRISPeriod(first, last string) (time.Time, time.Time, error) {
	parse := func(value string) (time.Time, error) {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed.UTC(), nil
		}
		// RIPEstat's documented JSON examples and baseline use UTC without Z.
		return time.Parse("2006-01-02T15:04:05", value)
	}
	start, startErr := parse(first)
	end, endErr := parse(last)
	if startErr != nil || endErr != nil || start.After(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("RIPEstat returned an invalid observation period")
	}
	return start, end, nil
}

func cloneASNInfo(info *model.ASNInfo) *model.ASNInfo {
	if info == nil {
		return nil
	}
	clone := *info
	if info.Announced != nil {
		announced := *info.Announced
		clone.Announced = &announced
	}
	clone.OverviewStart, clone.OverviewEnd = copyRoutingTime(info.OverviewStart), copyRoutingTime(info.OverviewEnd)
	if info.Prefixes != nil {
		prefixes := *info.Prefixes
		prefixes.Items = slices.Clone(prefixes.Items)
		prefixes.PeriodStart, prefixes.PeriodEnd = copyRoutingTime(prefixes.PeriodStart), copyRoutingTime(prefixes.PeriodEnd)
		prefixes.FetchedAt = copyRoutingTime(prefixes.FetchedAt)
		clone.Prefixes = &prefixes
	}
	return &clone
}

func copyRoutingTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
