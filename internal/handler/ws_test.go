package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"whois/internal/config"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

func init() {
	utils.TestInitLogger()
}

func dialHandlerWebSocket(t *testing.T, h *Handler) *websocket.Conn {
	t.Helper()
	e := echo.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		if err := h.HandleWS(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, response, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v (%#v)", err, response)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

func assertRequestIDFrames(t *testing.T, ws *websocket.Conn, expected map[string]string) {
	t.Helper()
	if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	seenDone := make(map[string]bool, len(expected))
	seenAllDone := make(map[string]bool, len(expected))
	for range 200 {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("read request frame: %v", err)
		}
		var message WSMessage
		if err := json.Unmarshal(payload, &message); err != nil {
			t.Fatalf("decode request frame: %v", err)
		}
		requestID, ok := expected[message.Target]
		if !ok {
			t.Fatalf("unexpected target-scoped frame: %#v", message)
		}
		if message.RequestID != requestID {
			t.Fatalf("target %q frame %q used request ID %q, want %q", message.Target, message.Type, message.RequestID, requestID)
		}
		if requestID == "" && bytes.Contains(payload, []byte(`"request_id"`)) {
			t.Fatalf("legacy frame unexpectedly serialized request_id: %s", payload)
		}
		switch message.Type {
		case "done":
			seenDone[message.Target] = true
		case "all_done":
			seenAllDone[message.Target] = true
		}
		if len(seenAllDone) == len(expected) {
			break
		}
	}
	for target := range expected {
		if !seenDone[target] {
			t.Errorf("target %q never received a done frame", target)
		}
		if !seenAllDone[target] {
			t.Errorf("target %q never received an all_done frame", target)
		}
	}
}

func websocketPortErrorRequest(requestID, target string) map[string]interface{} {
	return map[string]interface{}{
		"request_id": requestID,
		"targets":    []string{target},
		"config":     map[string]interface{}{"ports": "invalid"},
	}
}

func TestValidWSRequestID(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		want      bool
	}{
		{name: "legacy empty", requestID: "", want: true},
		{name: "allowed alphabet", requestID: "AZaz09._:-", want: true},
		{name: "maximum length", requestID: strings.Repeat("a", maxWSRequestIDBytes), want: true},
		{name: "too long", requestID: strings.Repeat("a", maxWSRequestIDBytes+1), want: false},
		{name: "space", requestID: "request id", want: false},
		{name: "slash", requestID: "request/id", want: false},
		{name: "unicode", requestID: "réquest", want: false},
		{name: "control", requestID: "request\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validWSRequestID(tt.requestID); got != tt.want {
				t.Fatalf("validWSRequestID(%q) = %v, want %v", tt.requestID, got, tt.want)
			}
		})
	}
}

func TestHandleWSRequestIDsDoNotCross(t *testing.T) {
	tests := []struct {
		name         string
		simultaneous bool
	}{
		{name: "sequential"},
		{name: "simultaneous", simultaneous: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{
				MaxTargetConcurrency:  4,
				MaxServiceConcurrency: 4,
			})
			ws := dialHandlerWebSocket(t, h)
			requests := []struct {
				requestID string
				target    string
			}{
				{requestID: "request:first", target: "example.com"},
				{requestID: "request-second_2", target: "example.org"},
			}

			if tt.simultaneous {
				expected := make(map[string]string, len(requests))
				for _, request := range requests {
					if err := ws.WriteJSON(websocketPortErrorRequest(request.requestID, request.target)); err != nil {
						t.Fatal(err)
					}
					expected[request.target] = request.requestID
				}
				assertRequestIDFrames(t, ws, expected)
				return
			}

			for _, request := range requests {
				if err := ws.WriteJSON(websocketPortErrorRequest(request.requestID, request.target)); err != nil {
					t.Fatal(err)
				}
				assertRequestIDFrames(t, ws, map[string]string{request.target: request.requestID})
			}
		})
	}
}

func TestHandleWSLegacyEmptyRequestID(t *testing.T) {
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	ws := dialHandlerWebSocket(t, h)
	if err := ws.WriteJSON(websocketPortErrorRequest("", "example.com")); err != nil {
		t.Fatal(err)
	}
	assertRequestIDFrames(t, ws, map[string]string{"example.com": ""})
}

func TestHandleWSRejectsInvalidRequestIDWithoutLaunchingQuery(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
	}{
		{name: "invalid character", requestID: "bad/request"},
		{name: "whitespace", requestID: "bad request"},
		{name: "unicode", requestID: "bad-é"},
		{name: "oversized", requestID: strings.Repeat("x", maxWSRequestIDBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
			ws := dialHandlerWebSocket(t, h)
			if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := ws.WriteJSON(websocketPortErrorRequest(tt.requestID, "must-not-launch.example")); err != nil {
				t.Fatal(err)
			}
			_, payload, err := ws.ReadMessage()
			if err != nil {
				t.Fatal(err)
			}
			var message WSMessage
			if err := json.Unmarshal(payload, &message); err != nil {
				t.Fatal(err)
			}
			if message.Type != "error" || message.Service != "system" || fmt.Sprint(message.Data) != "invalid request_id" {
				t.Fatalf("invalid request ID response = %#v", message)
			}
			if message.RequestID != "" || message.Target != "" || bytes.Contains(payload, []byte(tt.requestID)) {
				t.Fatalf("invalid request ID was reflected: %s", payload)
			}

			if err := ws.WriteJSON(websocketPortErrorRequest("sentinel:valid", "sentinel.example")); err != nil {
				t.Fatal(err)
			}
			assertRequestIDFrames(t, ws, map[string]string{"sentinel.example": "sentinel:valid"})
		})
	}
}

func TestHandleWSHeartbeatIgnoresRequestID(t *testing.T) {
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	ws := dialHandlerWebSocket(t, h)
	if err := ws.WriteJSON(map[string]string{"type": "heartbeat", "request_id": "ignored invalid/id"}); err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteJSON(websocketPortErrorRequest("after:heartbeat", "example.com")); err != nil {
		t.Fatal(err)
	}
	assertRequestIDFrames(t, ws, map[string]string{"example.com": "after:heartbeat"})
}

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
	var msg WSMessage
	if err := ws.ReadJSON(&msg); err != nil {
		t.Fatalf("reading invalid-message response: %v", err)
	}
	if msg.Type != "error" {
		t.Fatalf("invalid JSON response type = %q; want error", msg.Type)
	}

	// 2. Invalid Target
	input := struct {
		Targets []string `json:"targets"`
	}{Targets: []string{"invalid!"}}
	_ = ws.WriteJSON(input)

	for i := 0; i < 5; i++ {
		_ = ws.ReadJSON(&msg)
		if msg.Type == "error" {
			break
		}
	}

	_ = ws.Close()
}

func TestHandleWSKeepsReadingWhileTargetWaitsForCapacity(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{MaxTargetConcurrency: 1, MaxServiceConcurrency: 1})
	h.targetSem <- struct{}{}
	defer func() {
		select {
		case <-h.targetSem:
		default:
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.HandleWS(e.NewContext(r, w))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := ws.WriteJSON(map[string]interface{}{"targets": []string{"example.com"}}); err != nil {
		t.Fatalf("write queued target: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte("{invalid}")); err != nil {
		t.Fatalf("write follow-up message: %v", err)
	}

	var message WSMessage
	if err := ws.ReadJSON(&message); err != nil {
		t.Fatalf("read follow-up response while target is queued: %v", err)
	}
	if message.Type != "error" || message.Service != "system" {
		t.Fatalf("got %#v, want system error", message)
	}
}

func TestHandleWSBoundsQueuedTargets(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{MaxTargetConcurrency: 1, MaxServiceConcurrency: 1})
	h.targetSem <- struct{}{}
	defer func() { <-h.targetSem }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.HandleWS(e.NewContext(r, w))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	targets := make([]string, maxWSQueuedQueries)
	for i := range targets {
		targets[i] = fmt.Sprintf("target-%d.example", i)
	}
	if err := ws.WriteJSON(map[string]interface{}{"request_id": "queue:fill", "targets": targets}); err != nil {
		t.Fatalf("write queued targets: %v", err)
	}
	if err := ws.WriteJSON(map[string]interface{}{"request_id": "queue:overflow", "targets": []string{"overflow.example"}}); err != nil {
		t.Fatalf("write overflow target: %v", err)
	}

	var message WSMessage
	if err := ws.ReadJSON(&message); err != nil {
		t.Fatalf("read queue bound response: %v", err)
	}
	if message.Type != "error" || !strings.Contains(fmt.Sprint(message.Data), "too many queued targets") {
		t.Fatalf("got %#v, want queued-target limit error", message)
	}
	if message.RequestID != "queue:overflow" {
		t.Fatalf("queued-target error request ID = %q", message.RequestID)
	}
}

func TestHandleWSRejectsTooManyTargets(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		if err := h.HandleWS(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	targets := make([]string, maxWSTargets+1)
	for i := range targets {
		targets[i] = "example.com"
	}
	if err := ws.WriteJSON(map[string]interface{}{"request_id": "request:too-many", "targets": targets}); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}

	var message WSMessage
	if err := ws.ReadJSON(&message); err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	if message.Type != "error" || message.Service != "system" {
		t.Fatalf("got %#v, want system error", message)
	}
	if message.RequestID != "request:too-many" {
		t.Fatalf("too-many-target error request ID = %q", message.RequestID)
	}
}

func TestHandleWSEnforcesReadLimit(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.HandleWS(e.NewContext(r, w))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))

	if err := ws.WriteMessage(websocket.TextMessage, make([]byte, maxWSMessageBytes+1)); err != nil {
		t.Fatalf("write oversized websocket request: %v", err)
	}
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("oversized websocket request did not close the connection")
	}
}

func TestHandlerCloseWaitsForWebSocketsAndRejectsNewConnections(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		if err := h.HandleWS(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()

	h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.WaitForClose(ctx); err != nil {
		t.Fatalf("wait for websocket shutdown: %v", err)
	}

	_, response, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("new websocket connection succeeded after handler shutdown")
	}
	if response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("new websocket response = %#v, want HTTP %d", response, http.StatusServiceUnavailable)
	}
}

func TestHandleWSRejectsNonUpgradeRequest(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rec := httptest.NewRecorder()
	err := h.HandleWS(e.NewContext(req, rec))
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusBadRequest {
		t.Fatalf("HandleWS error = %#v, want HTTP 400", err)
	}
	h.wsConnMu.Lock()
	defer h.wsConnMu.Unlock()
	if h.wsActive != 0 {
		t.Fatalf("non-upgrade request reserved %d websocket slots", h.wsActive)
	}
}

func TestHandleWSRejectsHostileOriginAndReleasesReservation(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{
		MaxWSConnections:      1,
		MaxWSConnectionsPerIP: 1,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		if err := h.HandleWS(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	hostileHeader := http.Header{"Origin": []string{"https://evil.example"}}
	_, response, err := websocket.DefaultDialer.Dial(wsURL, hostileHeader)
	if err == nil {
		t.Fatal("hostile Origin completed a websocket handshake")
	}
	if response == nil {
		t.Fatalf("hostile Origin returned no HTTP response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("hostile Origin status = %d, want 403", response.StatusCode)
	}
	if got := string(body); got != http.StatusText(http.StatusForbidden)+"\n" {
		t.Fatalf("hostile Origin body = %q, want sanitized status text", got)
	}

	h.wsConnMu.Lock()
	active := h.wsActive
	reservedForIP := len(h.wsByIP)
	h.wsConnMu.Unlock()
	if active != 0 || reservedForIP != 0 {
		t.Fatalf("rejected handshake leaked reservation: active=%d client_entries=%d", active, reservedForIP)
	}

	allowedHeader := http.Header{"Origin": []string{srv.URL}}
	connection, allowedResponse, err := websocket.DefaultDialer.Dial(wsURL, allowedHeader)
	if err != nil {
		t.Fatalf("valid replacement handshake failed after rejection: %v (%#v)", err, allowedResponse)
	}
	_ = connection.Close()
}

func TestHandleWSEnforcesActiveConnectionLimits(t *testing.T) {
	e := echo.New()
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{
		SkipOriginCheck:       true,
		MaxWSConnections:      1,
		MaxWSConnectionsPerIP: 1,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		if err := h.HandleWS(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	first, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("first websocket: %v", err)
	}
	defer func() { _ = first.Close() }()

	_, response, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("second websocket bypassed active connection limit")
	}
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second websocket response = %#v, want HTTP 429", response)
	}

	_ = first.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.wsConnMu.Lock()
		active := h.wsActive
		h.wsConnMu.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	replacement, response, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("replacement websocket failed after release: %v (%#v)", err, response)
	}
	_ = replacement.Close()
}

func TestWebSocketReservationIsRaceSafeAndPerIPBounded(t *testing.T) {
	h := NewHandler(storage.NewStorage("localhost", "6379"), &config.Config{
		MaxWSConnections:      2,
		MaxWSConnectionsPerIP: 1,
	})
	if err := h.reserveWebSocket("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := h.reserveWebSocket("192.0.2.1"); err == nil {
		t.Fatal("per-IP websocket limit was not enforced")
	}
	if err := h.reserveWebSocket("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := h.reserveWebSocket("203.0.113.1"); err == nil {
		t.Fatal("global websocket limit was not enforced")
	}
	h.releaseWebSocket("192.0.2.1", nil)
	h.releaseWebSocket("198.51.100.1", nil)
}
