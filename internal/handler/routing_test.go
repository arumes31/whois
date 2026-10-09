package handler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"whois/internal/config"
	"whois/internal/model"
)

type routingLookupStub struct {
	calls  atomic.Int32
	result model.RoutingInfo
}

func (s *routingLookupStub) Lookup(_ context.Context, target string) model.RoutingInfo {
	s.calls.Add(1)
	result := s.result
	result.Query = target
	return result
}

func TestQueryItemRoutingRequiresBothOptIns(t *testing.T) {
	useLocalTargetEnrichment(t)
	fetched := time.Now().UTC()
	stub := &routingLookupStub{result: model.RoutingInfo{Status: "answer", IP: "1.1.1.1", Prefix: "1.1.1.0/24", OriginASNs: []uint32{13335}, FetchedAt: &fetched}}
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	h.Routing = stub
	for _, enabled := range []bool{false, true} {
		h.AppConfig.EnableRouting = enabled
		result := h.queryItem(context.Background(), "1.1.1.1", false, false, false, false, false, false, !enabled)
		if stub.calls.Load() != 0 || result.Routing != nil {
			t.Fatal("routing ran without both server and request opt-in")
		}
	}
	result := h.queryItem(context.Background(), "1.1.1.1", false, false, false, false, false, false, true)
	if stub.calls.Load() != 1 || result.Routing == nil || result.Routing.Status != "answer" {
		t.Fatalf("selected routing did not run independently of old cache: %+v", result)
	}
	result = h.queryItem(context.Background(), "1.1.1.1", false, false, false, false, false, false, false)
	if result.Routing != nil || stub.calls.Load() != 1 {
		t.Fatal("routing data leaked into an unselected response")
	}
}

func TestQueryItemRoutingOutageIsNotCached(t *testing.T) {
	useLocalTargetEnrichment(t)
	stub := &routingLookupStub{result: model.RoutingInfo{Status: "error", Error: "provider unavailable"}}
	h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableRouting: true})
	h.Routing = stub
	for range 2 {
		result := h.queryItem(context.Background(), "1.1.1.1", false, false, false, false, false, false, true)
		if result.Routing == nil || result.Routing.Error == "" {
			t.Fatalf("provider outage was hidden: %+v", result)
		}
	}
	if stub.calls.Load() != 2 {
		t.Fatal("provider outage was cached in aggregate query cache")
	}
}

func TestHandleWSRoutingOptInAndCompletion(t *testing.T) {
	useLocalTargetEnrichment(t)
	for _, tc := range []struct {
		name               string
		enabled, requested bool
	}{
		{"disabled on server", false, true},
		{"unchecked", true, false},
		{"opted in", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &routingLookupStub{result: model.RoutingInfo{Status: "no_announcement"}}
			h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableRouting: tc.enabled})
			h.Routing = stub
			ws := dialHandlerWebSocket(t, h)
			if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := ws.WriteJSON(map[string]interface{}{"targets": []string{"1.1.1.1"}, "request_id": "routing-request", "config": map[string]bool{"routing": tc.requested}}); err != nil {
				t.Fatal(err)
			}
			resultSeen, doneSeen := false, false
			for {
				var message WSMessage
				if err := ws.ReadJSON(&message); err != nil {
					t.Fatal(err)
				}
				if message.RequestID != "routing-request" {
					t.Fatalf("lost routing request ID: %+v", message)
				}
				if message.Service == "routing" {
					resultSeen = resultSeen || message.Type == "result"
					doneSeen = doneSeen || message.Type == "done"
				}
				if message.Type == "all_done" {
					break
				}
			}
			want := tc.enabled && tc.requested
			if resultSeen != want || doneSeen != want || (stub.calls.Load() > 0) != want {
				t.Fatalf("routing gate/completion mismatch: result=%v done=%v calls=%d", resultSeen, doneSeen, stub.calls.Load())
			}
		})
	}
}

func TestHandleWSRoutingPreservesLiteralInputAndSkippedCompletion(t *testing.T) {
	useLocalTargetEnrichment(t)
	stub := &routingLookupStub{result: model.RoutingInfo{Status: "skipped", Reason: "public literal IP required"}}
	h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableRouting: true})
	h.Routing = stub
	ws := dialHandlerWebSocket(t, h)
	if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	targets := []string{"https://1.1.1.1:443/path", "example.com", "AS13335", "1.1.1.0/24", "127.0.0.1"}
	if err := ws.WriteJSON(map[string]interface{}{"targets": targets, "request_id": "routing-skips", "config": map[string]bool{"routing": true}}); err != nil {
		t.Fatal(err)
	}
	results, done, allDone := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for len(allDone) < len(targets) {
		var message WSMessage
		if err := ws.ReadJSON(&message); err != nil {
			t.Fatal(err)
		}
		if message.RequestID != "routing-skips" {
			t.Fatalf("lost request ID: %+v", message)
		}
		if message.Type == "result" && message.Service == "routing" {
			data := message.Data.(map[string]interface{})
			if data["query"] != message.Target || data["status"] != "skipped" {
				t.Fatalf("routing received a normalized target instead of original literal input: %+v", message)
			}
			results[message.Target] = true
		}
		if message.Type == "done" && message.Service == "routing" {
			done[message.Target] = true
		}
		if message.Type == "all_done" {
			allDone[message.Target] = true
		}
	}
	if len(results) != len(targets) || len(done) != len(targets) {
		t.Fatalf("skipped target completion missing: results=%v done=%v", results, done)
	}
}
