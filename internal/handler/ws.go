package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
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
	defer func() {
		_ = ws.Close()
	}()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

		var input struct {
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
		_ = ws.WriteMessage(websocket.TextMessage, b)
		h.wsMu.Unlock()
	}

	sendLog := func(message string) {
		msg := WSMessage{
			Type:    "log",
			Target:  target,
			Service: "system",
			Data:    message,
		}
		b, _ := json.Marshal(msg)
		h.wsMu.Lock()
		_ = ws.WriteMessage(websocket.TextMessage, b)
		h.wsMu.Unlock()
	}

	sendLog("Initializing diagnostic chain for " + target)

	if cfg.Subdomains && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Discovering subdomains for " + target)
			send("subdomains", h.DNS.DiscoverSubdomains(target, nil))
			sendLog("Subdomain discovery completed for " + target)
		}()
	}

	if cfg.Route {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Starting traceroute to " + target)
			var lines []string
			service.Traceroute(ctx, target, func(line string) {
				lines = append(lines, line)
				send("route", lines)
			})
			sendLog("Traceroute completed for " + target)
		}()
	}

	if cfg.Trace && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Starting recursive DNS trace for " + target)
			res, _ := h.DNS.Trace(target)
			send("trace", res)
			sendLog("DNS trace completed for " + target)
		}()
	}

	if cfg.Ping {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Initiating ICMP ping to " + target)
			var lines []string
			service.Ping(ctx, target, 4, func(line string) {
				lines = append(lines, line)
				send("ping", lines) // Send updated lines
			})
			sendLog("Ping sequence finished for " + target)
		}()
	}

	if cfg.Whois && h.AppConfig.EnableWhois {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Querying WHOIS records for " + target)
			send("whois", service.Whois(target))
			sendLog("WHOIS data retrieved for " + target)
		}()
	}

	if cfg.DNS && h.AppConfig.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Resolving DNS records for " + target)
			d, err := h.DNS.Lookup(target, isIP)
			if err == nil {
				send("dns", d)
				_ = h.Storage.AddDNSHistory(ctx, target, d)
			} else {
				send("dns", map[string]string{"error": err.Error()})
				sendLog("DNS Error: " + err.Error())
			}
			sendLog("DNS resolution finished for " + target)
		}()
	}

	if cfg.CT && !isIP && h.AppConfig.EnableCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Searching Certificate Transparency logs for " + target)
			c, err := service.FetchCTSubdomains(target)
			if err == nil {
				send("ct", c)
			} else {
				send("ct", map[string]string{"error": err.Error()})
				sendLog("CT Error: " + err.Error())
			}
			sendLog("CT log search finished for " + target)
		}()
	}

	if cfg.SSL && h.AppConfig.EnableSSL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Analyzing SSL/TLS configuration for " + target)
			send("ssl", service.GetSSLInfo(target))
			sendLog("SSL/TLS analysis complete for " + target)
		}()
	}

	if cfg.HTTP && h.AppConfig.EnableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Inspecting HTTP response from " + target)
			send("http", service.GetHTTPInfo(target))
			sendLog("HTTP inspection finished for " + target)
		}()
	}

	if cfg.Geo && h.AppConfig.EnableGeo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Locating IP and ASN data for " + target)
			g, _ := service.GetGeoInfo(target)
			send("geo", g)
			sendLog("Geolocation data updated for " + target)
		}()
	}

	if cfg.Ports != "" && isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Starting port scan on " + target)
			var portList []int
			for _, p := range strings.Split(cfg.Ports, ",") {
				if i, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
					portList = append(portList, i)
				}
			}

			if len(portList) > 0 {
				results := make(map[int]string)
				service.ScanPortsStream(target, portList, func(port int, banner string, err error) {
					if err == nil {
						results[port] = banner
						send("portscan", results)
					}
				})
			}
			sendLog("Port scan completed for " + target)
		}()
	}

	go func() {
		wg.Wait()
		sendLog("All tasks completed for " + target)
	}()
}
