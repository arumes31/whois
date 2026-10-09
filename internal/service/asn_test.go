package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const asnOverviewFixture = `{"status":"ok","status_code":200,"data":{"type":"as","resource":"3333","holder":"RIPE NCC","announced":true,"query_starttime":"2026-10-09T08:00:00","query_endtime":"2026-10-09T08:00:00"}}`
const asnPrefixesFixture = `{"status":"ok","status_code":200,"data":{"resource":"3333","query_starttime":"2026-10-08T17:00:00","query_endtime":"2026-10-09T08:00:00","prefixes":[{"prefix":"193.0.0.0/21","timelines":[{"starttime":"2026-10-09T00:00:00","endtime":"2026-10-09T08:00:00"}]},{"prefix":"2001:67c:2e8::/48","timelines":[{"starttime":"2026-10-09T00:00:00","endtime":"2026-10-09T08:00:00"}]}]}}`

func asnFixtureService(t *testing.T, overview, prefixes string) (*RoutingService, *int) {
	t.Helper()
	s := NewRoutingService()
	s.now = func() time.Time { return time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC) }
	calls := 0
	var firstDeadline time.Time
	s.client.Transport = routingRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || request.URL.Host != "stat.ripe.net" || request.URL.Query().Get("resource") != "AS3333" {
			t.Errorf("unexpected provider request: %s", request.URL)
		}
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) > 3*time.Second {
			t.Error("ASN request is missing the bounded deadline")
		}
		if request.URL.Path == "/data/as-overview/data.json" {
			firstDeadline = deadline
		} else if !deadline.Equal(firstDeadline) {
			t.Error("prefix request reset the total ASN lookup deadline")
		}
		switch request.URL.Path {
		case "/data/as-overview/data.json":
			return routingResponse(overview), nil
		case "/data/announced-prefixes/data.json":
			q := request.URL.Query()
			if q.Get("min_peers_seeing") != "10" || q.Get("endtime") != "1791565200" || q.Get("starttime") != "1791478800" {
				t.Errorf("prefix period/visibility filter omitted: %s", request.URL)
			}
			return routingResponse(prefixes), nil
		default:
			t.Fatalf("unexpected ASN endpoint: %s", request.URL)
			return nil, nil
		}
	})
	return s, &calls
}

func TestASNLookupRetainsOverviewAndObservedIPv4IPv6Period(t *testing.T) {
	s, calls := asnFixtureService(t, asnOverviewFixture, asnPrefixesFixture)
	result := s.Lookup(context.Background(), "as0003333")
	if result.Status != "answer" || result.ASN == nil || result.ASN.Number != 3333 || result.ASN.Holder != "RIPE NCC" || result.ASN.Announced == nil || !*result.ASN.Announced {
		t.Fatalf("ASN overview lost: %+v", result)
	}
	prefixes := result.ASN.Prefixes
	if prefixes == nil || prefixes.Status != "answer" || len(prefixes.Items) != 2 || prefixes.PeriodStart == nil || prefixes.PeriodEnd == nil || prefixes.PeriodEnd.Hour() != 8 || prefixes.FetchedAt == nil {
		t.Fatalf("ASN prefix evidence lost: %+v", prefixes)
	}
	if result.SourceURL == prefixes.SourceURL || result.FetchedAt == nil || result.SnapshotCadenceHours != 0 || result.ASN.MinPeersSeeing != 10 || *calls != 2 {
		t.Fatalf("ASN source/cadence semantics incorrect: %+v", result)
	}
	// Cache hits must preserve provider times and must not share mutable data.
	result.ASN.Holder = "modified"
	*result.ASN.Announced = false
	prefixes.Items[0] = "0.0.0.0/0"
	*prefixes.PeriodEnd = time.Time{}
	second := s.Lookup(context.Background(), "AS3333")
	if *calls != 2 || second.Query != "AS3333" || second.ASN.Holder != "RIPE NCC" || !*second.ASN.Announced || second.ASN.Prefixes.Items[0] == "0.0.0.0/0" || second.ASN.Prefixes.PeriodEnd.IsZero() {
		t.Fatalf("cached ASN data was mutated or refetched: %+v calls=%d", second, *calls)
	}
}

func TestASNOverviewFalseDoesNotMeanInactive(t *testing.T) {
	overview := strings.Replace(asnOverviewFixture, `"announced":true`, `"announced":false`, 1)
	overview = strings.Replace(overview, `"holder":"RIPE NCC"`, `"holder":null`, 1)
	prefixes := `{"status":"ok","status_code":200,"data":{"resource":3333,"query_starttime":"2026-10-08T17:00:00Z","query_endtime":"2026-10-09T08:00:00Z","prefixes":[]}}`
	s, _ := asnFixtureService(t, overview, prefixes)
	result := s.Lookup(context.Background(), "AS3333")
	if result.Status != "answer" || result.ASN == nil || result.ASN.Announced == nil || *result.ASN.Announced || result.ASN.Prefixes.Status != "answer" || len(result.ASN.Prefixes.Items) != 0 {
		t.Fatalf("false origin observation misrepresented: %+v", result)
	}
}

func TestASNLookupRejectsInvalidOverview(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"wrong resource", strings.Replace(asnOverviewFixture, `"3333"`, `"13335"`, 1)},
		{"wrong type", strings.Replace(asnOverviewFixture, `"type":"as"`, `"type":"prefix"`, 1)},
		{"missing announced", strings.Replace(asnOverviewFixture, `"announced":true,`, "", 1)},
		{"missing resource", strings.Replace(asnOverviewFixture, `"resource":"3333",`, "", 1)},
		{"malformed period", strings.Replace(asnOverviewFixture, "2026-10-09T08:00:00", "not-a-time", 1)},
		{"reversed period", strings.Replace(asnOverviewFixture, "2026-10-09T08:00:00", "2026-10-10T08:00:00", 1)},
		{"bad status", strings.Replace(asnOverviewFixture, `"status":"ok"`, `"status":"maintenance"`, 1)},
		{"empty body", `{}`},
		{"oversized", asnOverviewFixture + strings.Repeat(" ", routingBodyLimit+1-len(asnOverviewFixture))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := asnFixtureService(t, tc.body, asnPrefixesFixture)
			for range 2 {
				result := s.Lookup(context.Background(), "AS3333")
				if result.Status != "error" || result.Error == "" || result.FetchedAt != nil {
					t.Fatalf("invalid overview accepted: %+v", result)
				}
				if tc.name == "oversized" && !strings.Contains(result.Error, "exceeds") {
					t.Fatalf("overview body limit was not applied: %+v", result)
				}
			}
			if *calls != 2 {
				t.Fatalf("invalid overview cached or prefix request made: calls=%d", *calls)
			}
		})
	}
}

func TestASNLookupKeepsOverviewWhenPrefixesFail(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"wrong resource", strings.Replace(asnPrefixesFixture, `"3333"`, `"13335"`, 1)},
		{"malformed prefix", strings.Replace(asnPrefixesFixture, "193.0.0.0/21", "not-a-prefix", 1)},
		{"host bits", strings.Replace(asnPrefixesFixture, "193.0.0.0/21", "193.0.0.1/21", 1)},
		{"mapped IPv4 prefix", strings.Replace(asnPrefixesFixture, "193.0.0.0/21", "::ffff:193.0.0.0/117", 1)},
		{"bad timeline", strings.Replace(asnPrefixesFixture, "2026-10-09T00:00:00", "2026-10-10T00:00:00", 1)},
		{"period outside request", strings.Replace(asnPrefixesFixture, "2026-10-08T17:00:00", "2026-10-01T17:00:00", 1)},
		{"null prefixes", `{"status":"ok","status_code":200,"data":{"resource":"3333","query_starttime":"2026-10-08T17:00:00","query_endtime":"2026-10-09T08:00:00","prefixes":null}}`},
		{"empty body", `{}`},
		{"oversized", asnPrefixesFixture + strings.Repeat(" ", asnPrefixesLimit+1-len(asnPrefixesFixture))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := asnFixtureService(t, asnOverviewFixture, tc.body)
			for range 2 {
				result := s.Lookup(context.Background(), "AS3333")
				if result.Status != "answer" || result.ASN == nil || result.ASN.Holder != "RIPE NCC" || result.ASN.Prefixes == nil || result.ASN.Prefixes.Status != "error" || result.ASN.Prefixes.Error == "" {
					t.Fatalf("prefix failure lost overview or implied no prefixes: %+v", result)
				}
				if RoutingCacheTTL(&result, s.now(), time.Minute) != 0 {
					t.Fatal("partial failure may be cached by aggregate query")
				}
				if tc.name == "oversized" && !strings.Contains(result.ASN.Prefixes.Error, "exceeds") {
					t.Fatalf("prefix body limit was not applied: %+v", result.ASN.Prefixes)
				}
			}
			if *calls != 4 {
				t.Fatalf("partial failure was cached: calls=%d", *calls)
			}
		})
	}
}

func TestASNLookupInvalidInputsDoNotRequestProvider(t *testing.T) {
	s := NewRoutingService()
	s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid ASN reached provider")
		return nil, nil
	})
	for _, target := range []string{"AS0", "AS4294967296", "AS-1", "AS+1", "AS1.5", "AS 3333", "AS", "AS１２３", "example.com", "https://AS3333"} {
		t.Run(target, func(t *testing.T) {
			result := s.Lookup(context.Background(), target)
			if result.Status != "skipped" && result.Status != "error" {
				t.Fatalf("invalid ASN accepted: %+v", result)
			}
		})
	}
}

func TestASNLookupCancellationAndSharedCacheBound(t *testing.T) {
	s, calls := asnFixtureService(t, asnOverviewFixture, asnPrefixesFixture)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := s.Lookup(ctx, "AS3333"); result.Status != "error" || !strings.Contains(result.Error, "canceled") || *calls != 0 {
		t.Fatalf("canceled ASN lookup reached provider: %+v calls=%d", result, *calls)
	}
	// ASN and IP entries share one process-service cache budget.
	s.Lookup(context.Background(), "AS3333")
	s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
		return routingResponse(`{"status":"ok","status_code":200,"data":{"prefix":"","asns":[]}}`), nil
	})
	for i := range 512 {
		s.Lookup(context.Background(), fmt.Sprintf("11.0.%d.%d", i/256, i%256))
	}
	if len(s.cache) != 512 {
		t.Fatalf("combined IP/ASN cache size=%d", len(s.cache))
	}
}

func TestASNCacheLimitsLargeEntriesAndExpires(t *testing.T) {
	s := NewRoutingService()
	now := time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	calls := 0
	s.client.Transport = routingRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		resource := strings.TrimPrefix(request.URL.Query().Get("resource"), "AS")
		body := asnOverviewFixture
		if request.URL.Path == "/data/announced-prefixes/data.json" {
			body = asnPrefixesFixture
		}
		return routingResponse(strings.Replace(body, `"resource":"3333"`, `"resource":"`+resource+`"`, 1)), nil
	})
	for i := range 33 {
		result := s.Lookup(context.Background(), fmt.Sprintf("AS%d", i+1))
		if result.Status != "answer" || result.ASN.Prefixes.Status != "answer" {
			t.Fatalf("ASN fixture failed: %+v", result)
		}
	}
	if len(s.cache) != 32 {
		t.Fatalf("large ASN entry cap not applied: %d", len(s.cache))
	}
	// The most recently added entry is present despite equal fixture timestamps.
	before := calls
	s.Lookup(context.Background(), "AS33")
	if calls != before {
		t.Fatal("fresh ASN entry not cached")
	}
	now = now.Add(time.Hour)
	s.Lookup(context.Background(), "AS33")
	if calls != before+2 {
		t.Fatal("ASN cache outlived its one-hour retrieval lifetime")
	}
}

func TestASNPositiveUint32EndpointsAndPrefixCancellation(t *testing.T) {
	for _, target := range []string{"AS1", "AS4294967295"} {
		t.Run(target, func(t *testing.T) {
			s := NewRoutingService()
			s.now = func() time.Time { return time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC) }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			s.client.Transport = routingRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Query().Get("resource") != target {
					t.Fatalf("ASN boundary changed: %s", request.URL)
				}
				if request.URL.Path == "/data/announced-prefixes/data.json" {
					cancel()
					return nil, request.Context().Err()
				}
				return routingResponse(strings.Replace(asnOverviewFixture, `"resource":"3333"`, `"resource":"`+target[2:]+`"`, 1)), nil
			})
			result := s.Lookup(ctx, target)
			if calls != 2 || result.Status != "answer" || result.ASN == nil || result.ASN.Holder == "" || result.ASN.Prefixes.Status != "error" || !strings.Contains(result.ASN.Prefixes.Error, "canceled") {
				t.Fatalf("cancellation lost successful overview: %+v calls=%d", result, calls)
			}
			if len(s.cache) != 0 {
				t.Fatal("canceled prefix result was cached")
			}
		})
	}
}
