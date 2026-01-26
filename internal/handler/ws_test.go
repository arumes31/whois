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
	cfg := &config.Config{EnableWhois: true, EnableDNS: true}
	h := NewHandler(store, cfg)
	
	// Create test server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		h.HandleWS(c)
	}))
	defer srv.Close()

	// Convert http URL to ws URL
	u := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Connect
	ws, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer ws.Close()

	// Send query
	input := struct {
		Targets []string `json:"targets"`
		Config  struct {
			Whois bool `json:"whois"`
			DNS   bool `json:"dns"`
		} `json:"config"`
	}{
		Targets: []string{"example.com"},
		Config: struct {
			Whois bool `json:"whois"`
			DNS   bool `json:"dns"`
		}{Whois: true, DNS: false},
	}
	
	err = ws.WriteJSON(input)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Receive response
	_, p, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}

	var msg WSMessage
	if err := json.Unmarshal(p, &msg); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if msg.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", msg.Target)
	}
	if msg.Service != "whois" {
		t.Errorf("Expected service whois, got %s", msg.Service)
	}
}
