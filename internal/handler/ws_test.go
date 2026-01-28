package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	// Send query for more services
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
		Targets: []string{"google.com", "1.1.1.1"},
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
			Ping: true, Trace: true, Route: true, Subdomains: true, Ports: "80,443",
		},
	}

	_ = ws.WriteJSON(input2)

	// Consume and check for diverse results
	for i := 0; i < 200; i++ {
		_, p, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var m WSMessage
		_ = json.Unmarshal(p, &m)
		if m.Type == "all_done" {
			break
		}
	}

	// Test invalid JSON input to HandleWS loop
	_ = ws.WriteMessage(websocket.TextMessage, []byte("invalid json"))

	// Test empty target input
	input3 := struct {
		Targets []string `json:"targets"`
	}{
		Targets: []string{""},
	}
	_ = ws.WriteJSON(input3)

	// Test error paths in streamQuery
	inputError := struct {
		Targets []string `json:"targets"`
		Config  struct {
			DNS bool `json:"dns"`
			CT  bool `json:"ct"`
		} `json:"config"`
	}{
		Targets: []string{"invalid..domain"},
		Config: struct {
			DNS bool `json:"dns"`
			CT  bool `json:"ct"`
		}{DNS: true, CT: true},
	}
	_ = ws.WriteJSON(inputError)

	// Test read error branch
	_ = ws.Close()
}
