package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"whois/internal/config"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func TestWebSocketHandshake(t *testing.T) {
	utils.TestInitLogger()
	e := echo.New()

	// Add same middlewares as main.go
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		ContentSecurityPolicy: "default-src 'self'; connect-src 'self' ws: wss:;",
	}))
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-CSRF-Token",
	}))

	cfg := &config.Config{
		SkipOriginCheck: true,
	}
	h := NewHandler(&storage.Storage{}, cfg)

	e.GET("/ws", h.HandleWS)

	srv := httptest.NewServer(e)
	defer srv.Close()

	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	t.Run("Standard Handshake", func(t *testing.T) {
		dialer := websocket.DefaultDialer
		conn, resp, err := dialer.Dial(u, nil)
		if err != nil {
			t.Fatalf("Handshake failed: %v (Status: %d)", err, resp.StatusCode)
		}
		_ = conn.Close()
	})

	t.Run("Handshake with Proxy Headers", func(t *testing.T) {
		dialer := websocket.DefaultDialer
		header := http.Header{}
		header.Set("X-Forwarded-Proto", "https")
		header.Set("X-Forwarded-Host", "whois-dev.reitetschlaeger.com")
		header.Set("Origin", "https://whois-dev.reitetschlaeger.com")

		conn, resp, err := dialer.Dial(u, header)
		if err != nil {
			if resp != nil {
				body, _ := io.ReadAll(resp.Body)
				t.Logf("Handshake failed with body: %s", string(body))
			}
			// If it fails with 400, it reproduces the issue
			t.Fatalf("Handshake with proxy headers failed: %v", err)
		}
		_ = conn.Close()
	})
}
