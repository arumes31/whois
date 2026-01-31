package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"whois/internal/config"
	"whois/internal/storage"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

func TestHandleWS(t *testing.T) {
	// Setup
	e := echo.New()
	store := storage.NewStorage("localhost", "6379")
	cfg := &config.Config{EnableWhois: true, EnableDNS: true, EnableGeo: true}
	h := NewHandler(store, cfg)

	// Create test server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		_ = h.HandleWS(c)
	}))
	defer srv.Close()

	// Convert http URL to ws URL
	u := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Connect
	ws, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer func() {
		_ = ws.Close()
	}()

	// Send query for Geo
	input := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Geo bool `json:"geo"`
		} `json:"config"`
	}{
		Targets: []string{"8.8.8.8"},
		Config: struct {
			Geo bool `json:"geo"`
		}{Geo: true},
	}

	err = ws.WriteJSON(input)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Receive response - look for geo result
	var msg WSMessage
	foundGeo := false
	for i := 0; i < 50; i++ {
		_, p, err := ws.ReadMessage()
		if err != nil {
			break
		}

		if err := json.Unmarshal(p, &msg); err != nil {
			continue
		}

		if msg.Type == "result" && msg.Service == "geo" {
			foundGeo = true
			break
		}
	}

	if !foundGeo {
		t.Log("Did not receive geo result in initial loop")
	}

	// Send query for all domain services
	input2 := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Whois      bool   `json:"whois"`
			DNS        bool   `json:"dns"`
			CT         bool   `json:"ct"`
			SSL        bool   `json:"ssl"`
			HTTP       bool   `json:"http"`
			Geo        bool   `json:"geo"`
			Ping       bool   `json:"ping"`
			Trace      bool   `json:"trace"`
			Route      bool   `json:"route"`
			Subdomains bool   `json:"subdomains"`
			Ports      string `json:"ports"`
		} `json:"config"`
	}{
		Targets: []string{"google.com"},
		Config: struct {
			Whois      bool   `json:"whois"`
			DNS        bool   `json:"dns"`
			CT         bool   `json:"ct"`
			SSL        bool   `json:"ssl"`
			HTTP       bool   `json:"http"`
			Geo        bool   `json:"geo"`
			Ping       bool   `json:"ping"`
			Trace      bool   `json:"trace"`
			Route      bool   `json:"route"`
			Subdomains bool   `json:"subdomains"`
			Ports      string `json:"ports"`
		}{
			Whois: true, DNS: true, CT: true, SSL: true, HTTP: true, Geo: true,
			Ping: true, Trace: true, Route: true, Subdomains: true, Ports: "",
		},
	}
	_ = ws.WriteJSON(input2)

	// Send query for IP services including port scan
	inputIP := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Geo   bool   `json:"geo"`
			Ports string `json:"ports"`
		} `json:"config"`
	}{
		Targets: []string{"8.8.8.8"},
		Config: struct {
			Geo   bool   `json:"geo"`
			Ports string `json:"ports"`
		}{Geo: true, Ports: "53"},
	}
	_ = ws.WriteJSON(inputIP)

	// Consume messages to trigger all-done
	for i := 0; i < 300; i++ {
		_, p, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var m WSMessage
		_ = json.Unmarshal(p, &m)
		if m.Type == "all_done" && m.Target == "8.8.8.8" {
			break
		}
	}

	// Test edge cases in streamQuery
	inputEdge := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Ports string `json:"ports"`
			CT    bool   `json:"ct"`
		} `json:"config"`
	}{
		// 1. Port scan on domain (should be skipped)
		// 2. CT on IP (should be skipped)
		Targets: []string{"google.com", "8.8.8.8"},
		Config: struct {
			Ports string `json:"ports"`
			CT    bool   `json:"ct"`
		}{Ports: "80", CT: true},
	}
	_ = ws.WriteJSON(inputEdge)

	// Test invalid port numbers
	inputBadPort := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Ports string `json:"ports"`
		} `json:"config"`
	}{
		Targets: []string{"8.8.8.8"},
		Config: struct {
			Ports string `json:"ports"`
		}{Ports: "invalid,99999"},
	}
	_ = ws.WriteJSON(inputBadPort)

	// Consume more messages
	for i := 0; i < 50; i++ {
		_, _, _ = ws.ReadMessage()
	}

	// Trigger read error by closing
	_ = ws.Close()
}

func TestHandleWS_FullFeatures(t *testing.T) {
	e := echo.New()
	store := storage.NewStorage("localhost", "6379")
	cfg := &config.Config{EnableWhois: true, EnableDNS: true, EnableGeo: true}
	h := NewHandler(store, cfg)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.HandleWS(e.NewContext(r, w))
	}))
	defer srv.Close()

	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, _ := websocket.DefaultDialer.Dial(u, nil)
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))

	input := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Ping       bool   `json:"ping"`
			Trace      bool   `json:"trace"`
			Route      bool   `json:"route"`
			Subdomains bool   `json:"subdomains"`
			Ports      string `json:"ports"`
		} `json:"config"`
	}{
		Targets: []string{"localhost"},
		Config: struct {
			Ping       bool   `json:"ping"`
			Trace      bool   `json:"trace"`
			Route      bool   `json:"route"`
			Subdomains bool   `json:"subdomains"`
			Ports      string `json:"ports"`
		}{Ping: true, Trace: true, Route: true, Subdomains: true, Ports: "80"},
	}
	_ = ws.WriteJSON(input)

	// Consume some messages
	for i := 0; i < 100; i++ {
		var m WSMessage
		err := ws.ReadJSON(&m)
		if err != nil {
			break
		}
		if m.Type == "all_done" {
			break
		}
	}
	_ = ws.Close()
}

func TestHandleWS_Errors(t *testing.T) {
	e := echo.New()
	store := storage.NewStorage("localhost", "6379")
	h := NewHandler(store, &config.Config{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.HandleWS(e.NewContext(r, w))
	}))
	defer srv.Close()

	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, _ := websocket.DefaultDialer.Dial(u, nil)
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 1. Invalid JSON
	_ = ws.WriteMessage(websocket.TextMessage, []byte("{invalid}"))
	time.Sleep(50 * time.Millisecond)

	// 2. Invalid Target
	input := struct {
		Targets []string `json:"targets"`
	}{Targets: []string{"invalid!"}}
	_ = ws.WriteJSON(input)

	var msg WSMessage
	for i := 0; i < 5; i++ {
		_ = ws.ReadJSON(&msg)
		if msg.Type == "error" {
			break
		}
	}

	_ = ws.Close()
}
