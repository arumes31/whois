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
		t.Error("Did not receive geo result via WebSocket")
	}
}
