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

			go h.streamQuery(c.Request().Context(), ws, target, input.Config)
		}
	}
	return nil
}

func (h *Handler) streamQuery(ctx context.Context, ws *websocket.Conn, target string, cfg struct {
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

	// Shared subdomain state
	subResults := make(map[string]interface{})
	var subMu sync.Mutex
	processedSubs := make(map[string]bool)
	var subProcessedMu sync.Mutex
	subSem := make(chan struct{}, 20)

	processSub := func(fqdn string, records map[string][]string) {
		subProcessedMu.Lock()
		if processedSubs[fqdn] {
			subProcessedMu.Unlock()
			return
		}
		processedSubs[fqdn] = true
		subProcessedMu.Unlock()

		if records == nil {
			select {
			case <-ctx.Done():
				return
			case subSem <- struct{}{}:
				defer func() { <-subSem }()
			}
			records = h.DNS.Resolve(ctx, fqdn)
		}

		if len(records) > 0 {
			subMu.Lock()
			subResults[fqdn] = records
			msgData := make(map[string]interface{})
			for k, v := range subResults {
				msgData[k] = v
			}
			subMu.Unlock()
			send("subdomains", msgData)
		}
	}

	// Helper to send completion status
	sendDone := func(serviceName string) {
		msg := WSMessage{
			Type:    "done",
			Target:  target,
			Service: serviceName,
		}
		b, _ := json.Marshal(msg)
		h.wsMu.Lock()
		_ = ws.WriteMessage(websocket.TextMessage, b)
		h.wsMu.Unlock()
	}

	if cfg.Subdomains && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Discovering subdomains for " + target)

			_ = h.DNS.DiscoverSubdomainsStream(ctx, target, nil, func(fqdn string, res map[string][]string) {
				processSub(fqdn, res)
			})

			sendLog("Subdomain discovery completed for " + target)
			sendDone("subdomains")
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
			sendDone("route")
		}()
	}

	if cfg.Trace && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Starting recursive DNS trace for " + target)
			res, _ := h.DNS.Trace(ctx, target)
			send("trace", res)
			sendLog("DNS trace completed for " + target)
			sendDone("trace")
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
				send("ping", lines)
			})
			sendLog("Ping sequence finished for " + target)
			sendDone("ping")
		}()
	}

	if cfg.Whois && h.AppConfig.EnableWhois {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Querying WHOIS records for " + target)
			send("whois", service.Whois(target))
			sendLog("WHOIS data retrieved for " + target)
			sendDone("whois")
		}()
	}

	if cfg.DNS && h.AppConfig.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Resolving DNS records for " + target)

			dnsData := make(map[string]interface{})
			var dmu sync.Mutex

			err := h.DNS.LookupStream(ctx, target, isIP, func(rtype string, data interface{}) {
				dmu.Lock()
				dnsData[rtype] = data
				// Create a copy for sending to avoid race condition during Marshal
				msgData := make(map[string]interface{})
				for k, v := range dnsData {
					msgData[k] = v
				}
				dmu.Unlock()
				send("dns", msgData)
			})

			if err != nil {
				send("dns", map[string]string{"error": err.Error()})
				sendLog("DNS Error: " + err.Error())
			} else {
				dmu.Lock()
				_ = h.Storage.AddDNSHistory(ctx, target, dnsData)
				dmu.Unlock()
			}
			sendLog("DNS resolution finished for " + target)
			sendDone("dns")
		}()
	}

	if cfg.CT && !isIP && h.AppConfig.EnableCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Searching Certificate Transparency logs for " + target)
			c, err := service.FetchCTSubdomains(ctx, target)
			if err == nil {
				send("ct", c)
				// Also add to subdomain discovery
				for sub := range c {
					wg.Add(1)
					go func(s string) {
						defer wg.Done()
						processSub(s, nil)
					}(sub)
				}
			} else {
				send("ct", map[string]string{"error": err.Error()})
				sendLog("CT Error: " + err.Error())
			}
			sendLog("CT log search finished for " + target)
			sendDone("ct")
		}()
	}

	if cfg.SSL && h.AppConfig.EnableSSL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Analyzing SSL/TLS configuration for " + target)
			send("ssl", service.GetSSLInfo(ctx, target))
			sendLog("SSL/TLS analysis complete for " + target)
			sendDone("ssl")
		}()
	}

	if cfg.HTTP && h.AppConfig.EnableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Inspecting HTTP response from " + target)
			send("http", service.GetHTTPInfo(ctx, target))
			sendLog("HTTP inspection finished for " + target)
			sendDone("http")
		}()
	}

	if cfg.Geo && h.AppConfig.EnableGeo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendLog("Locating IP and ASN data for " + target)
			g, _ := service.GetGeoInfo(ctx, target)
			send("geo", g)
			sendLog("Geolocation data updated for " + target)
			sendDone("geo")
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
				var pmu sync.Mutex
				foundOpen := false
				service.ScanPortsStream(ctx, target, portList, func(port int, banner string, err error) {
					if err == nil {
						pmu.Lock()
						results[port] = banner
						foundOpen = true
						// Create a copy for sending to avoid race condition during Marshal
						msgData := make(map[int]string)
						for k, v := range results {
							msgData[k] = v
						}
						pmu.Unlock()
						send("portscan", msgData)
					}
				})
				if !foundOpen {
					send("portscan", results)
				}
			}
			sendLog("Port scan completed for " + target)
			sendDone("portscan")
		}()
	}

	go func() {
		wg.Wait()
		sendLog("All tasks completed for " + target)

		// Final 'done' message for the whole card
		msg := WSMessage{
			Type:   "all_done",
			Target: target,
		}
		b, _ := json.Marshal(msg)
		h.wsMu.Lock()
		_ = ws.WriteMessage(websocket.TextMessage, b)
		h.wsMu.Unlock()
	}()
}
