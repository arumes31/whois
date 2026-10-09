package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"whois/internal/model"
)

type routingRoundTrip func(*http.Request) (*http.Response, error)

func (fn routingRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func routingResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestRoutingLookupValidatesProviderAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, target, body, status, prefix string
		asns                               int
	}{
		{"IPv4 multiple origins", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":["13335",13335,"64496"]}}`, "answer", "1.1.1.0/24", 2},
		{"IPv6", "2001:4860:4860::8888", `{"status":"ok","status_code":200,"data":{"prefix":"2001:4860::/32","asns":["15169"]}}`, "answer", "2001:4860::/32", 1},
		{"mapped IPv4", "::ffff:1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[13335]}}`, "answer", "1.1.1.0/24", 1},
		{"no announcement", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"","asns":[]}}`, "no_announcement", "", 0},
		{"null prefix", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":null,"asns":[]}}`, "no_announcement", "", 0},
		{"wrong prefix", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"8.8.8.0/24","asns":[15169]}}`, "error", "", 0},
		{"wrong family", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"::/0","asns":[15169]}}`, "error", "", 0},
		{"missing data", "1.1.1.1", `{"status":"ok","status_code":200}`, "error", "", 0},
		{"missing prefix", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"asns":[]}}`, "error", "", 0},
		{"missing origins", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":""}}`, "error", "", 0},
		{"null origins", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"","asns":null}}`, "error", "", 0},
		{"prefix without origins", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[]}}`, "error", "", 0},
		{"origins without prefix", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"","asns":[13335]}}`, "error", "", 0},
		{"zero ASN", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[0]}}`, "error", "", 0},
		{"overflow ASN", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[4294967296]}}`, "error", "", 0},
		{"fractional ASN", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[1.5]}}`, "error", "", 0},
		{"negative ASN", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[-1]}}`, "error", "", 0},
		{"maintenance", "1.1.1.1", `{"status":"maintenance","status_code":200,"data":{"prefix":"","asns":[]}}`, "error", "", 0},
		{"trailing document", "1.1.1.1", `{"status":"ok","status_code":200,"data":{"prefix":"","asns":[]}} {}`, "error", "", 0},
		{"oversized body", "1.1.1.1", strings.Repeat(" ", (128<<10)+1), "error", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewRoutingService()
			s.client.Transport = routingRoundTrip(func(request *http.Request) (*http.Response, error) {
				if request.URL.Scheme != "https" || request.URL.Host != "stat.ripe.net" || request.URL.Path != "/data/network-info/data.json" {
					t.Errorf("unexpected provider endpoint: %s", request.URL)
				}
				ip, _ := netip.ParseAddr(tc.target)
				if request.URL.Query().Get("resource") != ip.Unmap().String() {
					t.Errorf("wrong resource: %s", request.URL)
				}
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) > 3*time.Second {
					t.Error("provider request has no bounded total deadline")
				}
				return routingResponse(tc.body), nil
			})
			result := s.Lookup(context.Background(), tc.target)
			if result.Status != tc.status || result.Prefix != tc.prefix || len(result.OriginASNs) != tc.asns {
				t.Fatalf("unexpected routing result: %+v", result)
			}
			if result.Query != tc.target || result.Source == "" || result.SourceURL == "" || result.SnapshotCadenceHours != 8 {
				t.Fatalf("missing provenance: %+v", result)
			}
			if (result.FetchedAt != nil) != (tc.status != "error") || (result.Error != "") != (tc.status == "error") {
				t.Fatalf("error/observation semantics are inconsistent: %+v", result)
			}
		})
	}
}

func TestRoutingLookupSkipsNonPublicAndNonLiteralTargets(t *testing.T) {
	s := NewRoutingService()
	s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("ineligible target reached the provider")
		return nil, nil
	})
	for _, target := range []string{"example.com", "1.1.1.0/24", "127.0.0.1", "::1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "2001:db8::1", "ff02::1", "fe80::1%eth0", "http://1.1.1.1", "1.1.1.1:443"} {
		t.Run(target, func(t *testing.T) {
			result := s.Lookup(context.Background(), target)
			if result.Status != "skipped" || result.Reason == "" || result.FetchedAt != nil || result.SourceURL != "" {
				t.Fatalf("ineligible target result: %+v", result)
			}
		})
	}
}

func TestRoutingCacheExpiryAndResultIsolation(t *testing.T) {
	s := NewRoutingService()
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	calls := 0
	s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return routingResponse(`{"status":"ok","status_code":200,"data":{"prefix":"1.1.1.0/24","asns":[13335]}}`), nil
	})
	first := s.Lookup(context.Background(), "1.1.1.1")
	first.OriginASNs[0] = 1
	*first.FetchedAt = now.Add(-time.Hour)
	now = now.Add(59 * time.Minute)
	second := s.Lookup(context.Background(), "::ffff:1.1.1.1")
	if calls != 1 || second.OriginASNs[0] != 13335 || second.Query != "::ffff:1.1.1.1" || second.IP != "1.1.1.1" || now.Sub(*second.FetchedAt) != 59*time.Minute {
		t.Fatalf("cache lost isolation/provenance: calls=%d result=%+v", calls, second)
	}
	now = now.Add(time.Minute)
	third := s.Lookup(context.Background(), "1.1.1.1")
	if calls != 2 || !third.FetchedAt.Equal(now) {
		t.Fatalf("expired result was reused: calls=%d result=%+v", calls, third)
	}
}

func TestRoutingOutagesAndRedirectsAreNotCached(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := NewRoutingService()
			calls := 0
			s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				response := routingResponse("upstream unavailable")
				response.StatusCode = code
				response.Header.Set("Location", "http://127.0.0.1/private")
				return response, nil
			})
			for range 2 {
				if result := s.Lookup(context.Background(), "1.1.1.1"); result.Status != "error" || result.Error == "" || result.FetchedAt != nil {
					t.Fatalf("outage reported as routing evidence: %+v", result)
				}
			}
			if calls != 2 {
				t.Fatalf("expected one provider request per lookup, got %d", calls)
			}
		})
	}
}

func TestRoutingConcurrencyAndQueuedCancellation(t *testing.T) {
	s := NewRoutingService()
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	defer close(release)
	var active, maximum atomic.Int32
	s.client.Transport = routingRoundTrip(func(request *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for previous := maximum.Load(); n > previous && !maximum.CompareAndSwap(previous, n); previous = maximum.Load() {
		}
		entered <- struct{}{}
		select {
		case <-release:
			return routingResponse(`{"status":"ok","status_code":200,"data":{"prefix":"","asns":[]}}`), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() { s.Lookup(ctx, fmt.Sprintf("1.1.1.%d", i+1)) })
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request slots were not filled")
		}
	}
	queuedCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	queued := s.Lookup(queuedCtx, "8.8.8.8")
	if queued.Status != "error" || !strings.Contains(queued.Error, "deadline exceeded") || maximum.Load() != 4 {
		t.Fatalf("queued cancellation/limit failed: %+v max=%d", queued, maximum.Load())
	}
	select {
	case <-entered:
		t.Fatal("canceled queued request reached provider")
	default:
	}
	cancel()
	wg.Wait()
}

func TestRoutingAggregateCacheCannotExtendProviderLifetime(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, status string
		age          time.Duration
		want         time.Duration
	}{
		{"recent answer", "answer", time.Minute, 10 * time.Minute},
		{"near expiry", "answer", 59 * time.Minute, time.Minute},
		{"negative evidence", "no_announcement", 59 * time.Minute, time.Minute},
		{"expired", "answer", time.Hour, 0},
		{"future retrieval", "answer", -time.Minute, 0},
		{"outage", "error", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetched := now.Add(-tc.age)
			result := &model.RoutingInfo{Status: tc.status, FetchedAt: &fetched}
			if got := RoutingCacheTTL(result, now, 10*time.Minute); got != tc.want {
				t.Fatalf("aggregate cache lifetime = %v, want %v", got, tc.want)
			}
		})
	}
	if RoutingCacheTTL(nil, now, time.Minute) != 0 || RoutingCacheTTL(&model.RoutingInfo{Status: "answer"}, now, time.Minute) != 0 {
		t.Fatal("missing routing evidence was cacheable")
	}
}

func TestRoutingCacheIsBounded(t *testing.T) {
	s := NewRoutingService()
	s.client.Transport = routingRoundTrip(func(*http.Request) (*http.Response, error) {
		return routingResponse(`{"status":"ok","status_code":200,"data":{"prefix":"","asns":[]}}`), nil
	})
	for i := range 513 {
		target := fmt.Sprintf("11.0.%d.%d", i/256, i%256)
		if result := s.Lookup(context.Background(), target); result.Status != "no_announcement" {
			t.Fatalf("lookup %s: %+v", target, result)
		}
	}
	if len(s.cache) != 512 {
		t.Fatalf("cache grew beyond bound: %d", len(s.cache))
	}
}
