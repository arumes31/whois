package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"whois/internal/service"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WSMessage struct {
	Type    string      `json:"type"`
	Target  string      `json:"target"`
	Service string      `json:"service"`
	Data    interface{} `json:"data"`
}

func (h *Handler) HandleWS(c echo.Context) error {
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

		var input struct {
			Targets []string `json:"targets"`
			Config  struct {
				Whois bool `json:"whois"`
				DNS   bool `json:"dns"`
				CT    bool `json:"ct"`
				SSL   bool `json:"ssl"`
				HTTP  bool `json:"http"`
				Geo   bool `json:"geo"`
				Ping  bool `json:"ping"`
				Trace bool `json:"trace"`
				Route bool `json:"route"`
			} `json:"config"`
		}

		if err := json.Unmarshal(msg, &input); err != nil {
			continue
		}

		for _, target := range input.Targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			go h.streamQuery(ws, target, input.Config)
		}
	}
	return nil
}

func (h *Handler) streamQuery(ws *websocket.Conn, target string, cfg struct {
	Whois bool `json:"whois"`
	DNS   bool `json:"dns"`
	CT    bool `json:"ct"`
	SSL   bool `json:"ssl"`
	HTTP  bool `json:"http"`
	Geo   bool `json:"geo"`
	Ping  bool `json:"ping"`
	Trace bool `json:"trace"`
	Route bool `json:"route"`
}) {
	var wg sync.WaitGroup
	ctx := context.Background()
	isIP := net.ParseIP(target) != nil

	// Helper to send message
	send := func(serviceName string, data interface{}) {
		msg := WSMessage{
			Type:    "result",
			Target:  target,
			Service: serviceName,
			Data:    data,
		}
		b, _ := json.Marshal(msg)
		h.wsMu.Lock()
		ws.WriteMessage(websocket.TextMessage, b)
		h.wsMu.Unlock()
	}

	if cfg.Route {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lines []string
			service.Traceroute(ctx, target, func(line string) {
				lines = append(lines, line)
				send("route", lines)
			})
		}()
	}

	if cfg.Trace && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _ := h.DNS.Trace(target)
			send("trace", res)
		}()
	}

	if cfg.Ping {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lines []string
			service.Ping(ctx, target, 4, func(line string) {
				lines = append(lines, line)
				send("ping", lines) // Send updated lines
			})
		}()
	}

	if cfg.Whois && h.AppConfig.EnableWhois {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send("whois", service.Whois(target))
		}()
	}

	if cfg.DNS && h.AppConfig.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := h.DNS.Lookup(target, isIP)
			if err == nil {
				send("dns", d)
				h.Storage.AddDNSHistory(ctx, target, d)
			}
		}()
	}

	if cfg.CT && !isIP && h.AppConfig.EnableCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := service.FetchCTSubdomains(target)
			if err == nil {
				send("ct", c)
			}
		}()
	}

	if cfg.SSL && h.AppConfig.EnableSSL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send("ssl", service.GetSSLInfo(target))
		}()
	}

	if cfg.HTTP && h.AppConfig.EnableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send("http", service.GetHTTPInfo(target))
		}()
	}

	if cfg.Geo && h.AppConfig.EnableGeo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, _ := service.GetGeoInfo(target)
			send("geo", g)
		}()
	}

	wg.Wait()
}
