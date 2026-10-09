package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"whois/internal/config"
	"whois/internal/model"
)

func TestProfileAndBlockedTargetsNeverRunHostDiagnostics(t *testing.T) {
	for _, target := range []string{"192.168.1.23/24", "2001:db8::1/64", "AS13335", "127.0.0.1", "8.8.8.8/33"} {
		for _, enabled := range []bool{false, true} {
			h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableRouting: enabled})
			stub := &routingLookupStub{result: model.RoutingInfo{Status: "answer"}}
			h.Routing = stub
			result := h.queryItem(context.Background(), target, true, true, true, true, true, true, true)
			if result.DNS != nil || result.Whois != nil || result.CT != nil || result.HTTP != nil || result.SSL != nil || result.Geo != nil {
				t.Fatalf("host diagnostics ran for %s: %+v", target, result)
			}
			if (result.Routing != nil) != enabled {
				t.Fatalf("routing opt-in not respected: %+v", result)
			}
		}
	}
}

func TestIndexExportsSubnetWithoutRouting(t *testing.T) {
	e, _ := setupTestEcho()
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	form := url.Values{"ips_and_domains": {"192.168.1.23/24,2001:db8::1/64"}, "export": {"json"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if err := h.Index(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	var results map[string]struct {
		Target struct {
			Subnet map[string]interface{} `json:"subnet"`
		} `json:"target"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results["192.168.1.23/24"].Target.Subnet["address_count"] != "256" || results["2001:db8::1/64"].Target.Subnet["address_count"] != "18446744073709551616" {
		t.Fatalf("local calculator missing from JSON export: %s", rec.Body.String())
	}
}

func TestWebSocketASNReportsRoutingCapability(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, requested := range []bool{false, true} {
			h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableRouting: enabled})
			stub := &routingLookupStub{result: model.RoutingInfo{Status: "answer"}}
			h.Routing = stub
			ws := dialHandlerWebSocket(t, h)
			if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := ws.WriteJSON(map[string]interface{}{"targets": []string{"AS13335"}, "request_id": "asn", "config": map[string]bool{"routing": requested, "dns": true, "http": true}}); err != nil {
				t.Fatal(err)
			}
			profileSeen, routingSeen := false, false
			for {
				var message WSMessage
				if err := ws.ReadJSON(&message); err != nil {
					t.Fatal(err)
				}
				if message.Type == "result" {
					switch message.Service {
					case "target":
						profileSeen = true
						data := message.Data.(map[string]interface{})
						if data["routing_allowed"] != (enabled && requested) || data["query_allowed"] != false {
							t.Fatalf("ASN capability incorrectly reported: %+v", data)
						}
					case "routing":
						routingSeen = true
					default:
						t.Fatalf("host diagnostic ran for ASN: %+v", message)
					}
				}
				if message.Type == "all_done" {
					break
				}
			}
			if !profileSeen || routingSeen != (enabled && requested) {
				t.Fatalf("ASN result lifecycle incomplete: profile=%v routing=%v", profileSeen, routingSeen)
			}
		}
	}
}

func TestWebSocketSubnetWorksWithoutModules(t *testing.T) {
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	ws := dialHandlerWebSocket(t, h)
	if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteJSON(map[string]interface{}{"targets": []string{"::1/0"}, "request_id": "subnet"}); err != nil {
		t.Fatal(err)
	}
	profileSeen := false
	for {
		var message WSMessage
		if err := ws.ReadJSON(&message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "result" {
			if message.Service != "target" {
				t.Fatalf("unexpected network diagnostic: %+v", message)
			}
			profileSeen = true
			data := message.Data.(map[string]interface{})
			subnet := data["subnet"].(map[string]interface{})
			if subnet["address_count"] != "340282366920938463463374607431768211456" {
				t.Fatalf("IPv6 precision lost over WebSocket: %+v", subnet)
			}
		}
		if message.Type == "all_done" {
			break
		}
	}
	if !profileSeen {
		t.Fatal("missing local calculator result")
	}
}
