package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"whois/internal/model"
	"whois/internal/service"
	"whois/internal/utils"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

type WSMessage struct {
	Type      string      `json:"type"`
	RequestID string      `json:"request_id,omitempty"`
	Target    string      `json:"target"`
	Service   string      `json:"service"`
	Data      interface{} `json:"data"`
}

type wsQueryConfig struct {
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
}

const (
	maxWSMessageBytes   = 64 << 10
	maxWSTargets        = 25
	maxWSActiveQueries  = 4
	maxWSQueuedQueries  = 25
	maxCTResolveTargets = 100
	wsWriteWait         = 10 * time.Second
	maxWSRequestIDBytes = 128
)

func validWSRequestID(requestID string) bool {
	if len(requestID) > maxWSRequestIDBytes {
		return false
	}
	for i := range len(requestID) {
		char := requestID[i]
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}
	return true
}

type wsWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *wsWriter) write(messageType int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.SetWriteDeadline(time.Now().Add(wsWriteWait)); err != nil {
		return err
	}
	return w.conn.WriteMessage(messageType, data)
}

func (h *Handler) HandleWS(c echo.Context) error {
	if !websocket.IsWebSocketUpgrade(c.Request()) {
		return echo.NewHTTPError(http.StatusBadRequest, "websocket upgrade required")
	}

	utils.Log.Info("websocket handshake start",
		utils.Field("host", c.Request().Host),
		utils.Field("remote_addr", c.Request().RemoteAddr),
		utils.Field("proto", c.Request().Proto),
		utils.Field("uri", c.Request().RequestURI),
		utils.Field("origin", c.Request().Header.Get("Origin")),
		utils.Field("user_agent", c.Request().UserAgent()),
	)

	clientIP := utils.ExtractIP(c, utils.ProxyConfig{
		TrustProxy:    h.AppConfig.TrustProxy,
		UseCloudflare: h.AppConfig.UseCloudflare,
	})
	if err := h.reserveWebSocket(clientIP); err != nil {
		return err
	}

	ws, err := h.Upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		h.releaseWebSocket(clientIP, nil)
		return nil
	}
	h.wsConnMu.Lock()
	if h.wsClosing {
		h.wsConnMu.Unlock()
		_ = ws.Close()
		h.releaseWebSocket(clientIP, nil)
		return nil
	}
	h.wsConns[ws] = struct{}{}
	h.wsConnMu.Unlock()
	defer h.releaseWebSocket(clientIP, ws)
	ws.SetReadLimit(maxWSMessageBytes)
	writer := &wsWriter{conn: ws}
	ctx, cancel := context.WithCancel(c.Request().Context())
	var queryWG sync.WaitGroup
	defer func() {
		cancel()
		queryWG.Wait()
	}()
	activeLimit := maxWSActiveQueries
	if globalLimit := cap(h.targetSem); globalLimit > 0 && globalLimit < activeLimit {
		activeLimit = globalLimit
	}
	activeQueries := make(chan struct{}, activeLimit)
	querySlots := make(chan struct{}, maxWSQueuedQueries)

	// Heartbeat configuration
	pingPeriod := 30 * time.Second
	readWait := 60 * time.Second
	_ = ws.SetReadDeadline(time.Now().Add(readWait))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(readWait))
		return nil
	})

	// Background ping goroutine
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writer.write(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err,
				websocket.CloseNormalClosure,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
			) {
				utils.Log.Warn("websocket read error", utils.Field("error", err.Error()))
			}
			break
		}

		var input struct {
			Type      string        `json:"type"`
			RequestID string        `json:"request_id"`
			Targets   []string      `json:"targets"`
			Config    wsQueryConfig `json:"config"`
		}

		if err := json.Unmarshal(msg, &input); err != nil {
			payload, _ := json.Marshal(WSMessage{Type: "error", Service: "system", Data: "invalid websocket message"})
			_ = writer.write(websocket.TextMessage, payload)
			continue
		}

		if input.Type == "heartbeat" {
			_ = ws.SetReadDeadline(time.Now().Add(readWait))
			continue
		}
		if !validWSRequestID(input.RequestID) {
			payload, _ := json.Marshal(WSMessage{Type: "error", Service: "system", Data: "invalid request_id"})
			_ = writer.write(websocket.TextMessage, payload)
			continue
		}

		if len(input.Targets) > maxWSTargets {
			payload, _ := json.Marshal(WSMessage{Type: "error", RequestID: input.RequestID, Service: "system", Data: "too many targets; maximum is " + strconv.Itoa(maxWSTargets)})
			_ = writer.write(websocket.TextMessage, payload)
			continue
		}
		seenTargets := make(map[string]struct{}, len(input.Targets))
		for _, target := range input.Targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}
			targetInfo := utils.NormalizeTarget(target)
			identity := targetInfo.Scheme + "|" + targetInfo.Normalized
			if !targetInfo.Valid {
				identity = target
			}
			if _, exists := seenTargets[identity]; exists {
				continue
			}
			seenTargets[identity] = struct{}{}
			select {
			case querySlots <- struct{}{}:
			case <-ctx.Done():
				return nil
			default:
				payload, _ := json.Marshal(WSMessage{Type: "error", RequestID: input.RequestID, Target: target, Service: "system", Data: "too many queued targets; maximum is " + strconv.Itoa(maxWSQueuedQueries)})
				_ = writer.write(websocket.TextMessage, payload)
				continue
			}
			queryWG.Add(1)
			go func(target string, queryConfig wsQueryConfig, requestID string) {
				defer queryWG.Done()
				defer func() { <-querySlots }()
				select {
				case <-ctx.Done():
					return
				case activeQueries <- struct{}{}:
				}
				defer func() { <-activeQueries }()
				select {
				case <-ctx.Done():
					return
				case h.targetSem <- struct{}{}:
				}
				defer func() { <-h.targetSem }()
				h.streamQuery(ctx, writer, target, queryConfig, requestID)
			}(target, input.Config, input.RequestID)
		}
	}
	return nil
}

func (h *Handler) reserveWebSocket(clientIP string) error {
	h.wsConnMu.Lock()
	defer h.wsConnMu.Unlock()

	if h.wsClosing {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "server is shutting down")
	}
	if h.wsActive >= h.maxWSConns {
		return echo.NewHTTPError(http.StatusTooManyRequests, "websocket connection limit reached")
	}
	if h.wsByIP[clientIP] >= h.maxWSPerIP {
		return echo.NewHTTPError(http.StatusTooManyRequests, "websocket connection limit reached for client")
	}

	h.wsActive++
	h.wsByIP[clientIP]++
	h.wsWG.Add(1)
	return nil
}

func (h *Handler) releaseWebSocket(clientIP string, connection *websocket.Conn) {
	if connection != nil {
		_ = connection.Close()
	}

	h.wsConnMu.Lock()
	if connection != nil {
		delete(h.wsConns, connection)
	}
	if h.wsActive > 0 {
		h.wsActive--
	}
	if h.wsByIP[clientIP] <= 1 {
		delete(h.wsByIP, clientIP)
	} else {
		h.wsByIP[clientIP]--
	}
	h.wsConnMu.Unlock()
	h.wsWG.Done()
}

func (h *Handler) streamQuery(ctx context.Context, writer *wsWriter, target string, cfg wsQueryConfig, requestID string) {
	cardTarget := target
	targetInfo := utils.EnrichTarget(ctx, target)
	endpointTarget := targetInfo.Normalized
	httpTarget := cardTarget
	if targetInfo.Networkable {
		target = targetInfo.Host
	}
	var wg sync.WaitGroup
	isIP := targetInfo.Kind == model.TargetKindIPv4 || targetInfo.Kind == model.TargetKindIPv6

	// Helper to send message
	send := func(serviceName string, data interface{}) {
		msg := WSMessage{
			Type:      "result",
			RequestID: requestID,
			Target:    cardTarget,
			Service:   serviceName,
			Data:      data,
		}
		b, _ := json.Marshal(msg)
		_ = writer.write(websocket.TextMessage, b)
	}

	sendLog := func(message string) {
		msg := WSMessage{
			Type:      "log",
			RequestID: requestID,
			Target:    cardTarget,
			Service:   "system",
			Data:      message,
		}
		b, _ := json.Marshal(msg)
		_ = writer.write(websocket.TextMessage, b)
	}

	send("target", targetInfo)
	if !targetInfo.Valid || !targetInfo.Networkable || !utils.IsValidTarget(target) {
		reason := targetInfo.Error
		if reason == "" {
			reason = "this target type is profile-only in provider-free mode"
		}
		sendLog("Target cannot be queried: " + reason)
		msg := WSMessage{Type: "all_done", RequestID: requestID, Target: cardTarget}
		b, _ := json.Marshal(msg)
		_ = writer.write(websocket.TextMessage, b)
		return
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
			sendLog("Resolving DNS for discovered subdomain: " + fqdn)
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
			sendLog("Confirmed subdomain: " + fqdn + " (" + strconv.Itoa(len(records)) + " records)")
		}
	}

	// Helper to send completion status
	sendDone := func(serviceName string) {
		msg := WSMessage{
			Type:      "done",
			RequestID: requestID,
			Target:    cardTarget,
			Service:   serviceName,
		}
		b, _ := json.Marshal(msg)
		_ = writer.write(websocket.TextMessage, b)
	}
	acquireService := func() bool {
		select {
		case <-ctx.Done():
			return false
		case h.serviceSem <- struct{}{}:
			return true
		}
	}
	releaseService := func() { <-h.serviceSem }

	if cfg.Subdomains && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Discovering subdomains for " + target)

			err := h.DNS.DiscoverSubdomainsStream(ctx, target, nil, func(fqdn string, res map[string][]string) {
				processSub(fqdn, res)
			})
			if err != nil {
				send("subdomains", map[string]string{"error": err.Error()})
			} else {
				subMu.Lock()
				finalResults := make(map[string]interface{}, len(subResults))
				for name, records := range subResults {
					finalResults[name] = records
				}
				subMu.Unlock()
				send("subdomains", finalResults)
			}

			sendLog("Subdomain discovery completed for " + target)
			sendDone("subdomains")
		}()
	}

	if cfg.Route {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Starting traceroute to " + target)
			var lines []string
			err := service.Traceroute(ctx, target, func(line string) {
				lines = append(lines, line)
				send("route", lines)
			})
			if err != nil {
				send("route", map[string]interface{}{"error": err.Error(), "lines": lines})
			} else {
				send("route", lines)
			}
			sendLog("Traceroute completed for " + target)
			sendDone("route")
		}()
	}

	if cfg.Trace && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Starting recursive DNS trace for " + target)
			res, err := h.DNS.Trace(ctx, target)
			if err != nil {
				send("trace", map[string]interface{}{"error": err.Error(), "lines": res})
			} else {
				send("trace", res)
			}
			sendLog("DNS trace completed for " + target)
			sendDone("trace")
		}()
	}

	if cfg.Ping {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Initiating ICMP ping to " + target)
			var lines []string
			err := service.Ping(ctx, target, 4, func(line string) {
				lines = append(lines, line)
				send("ping", lines)
			})
			if err != nil {
				send("ping", map[string]interface{}{"error": err.Error(), "lines": lines})
			} else {
				send("ping", lines)
			}
			sendLog("Ping sequence finished for " + target)
			sendDone("ping")
		}()
	}

	if cfg.Whois && h.AppConfig.EnableWhois {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Querying WHOIS records for " + target)
			send("whois", service.Whois(ctx, target))
			sendLog("WHOIS data retrieved for " + target)
			sendDone("whois")
		}()
	}

	if cfg.DNS && h.AppConfig.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
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

				if list, ok := data.([]string); ok && len(list) > 0 {
					sendLog("Found " + rtype + " record: " + list[0])
				}
			})

			if err != nil {
				send("dns", map[string]string{"error": err.Error()})
				sendLog("DNS Error: " + err.Error())
			} else {
				dmu.Lock()
				historyData := make(map[string]interface{}, len(dnsData))
				for recordType, data := range dnsData {
					historyData[recordType] = data
				}
				dmu.Unlock()
				send("dns", historyData)
				h.recordDNSHistory(ctx, target, historyData, sendLog)
			}
			sendLog("DNS resolution finished for " + target)
			sendDone("dns")
		}()
	}

	if cfg.CT && !isIP && h.AppConfig.EnableCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Searching Certificate Transparency logs for " + target)
			c, err := service.FetchCTSubdomains(ctx, target)
			if err == nil {
				send("ct", c)
				// Also add to subdomain discovery
				resolvedCount := 0
				for sub := range c {
					if resolvedCount >= maxCTResolveTargets {
						sendLog("CT enrichment limited to " + strconv.Itoa(maxCTResolveTargets) + " subdomains; the complete CT list remains available above")
						break
					}
					processSub(sub, nil)
					resolvedCount++
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
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Analyzing SSL/TLS configuration for " + endpointTarget)
			res := service.GetSSLInfo(ctx, endpointTarget)
			send("ssl", res)
			if res.Protocol != "" {
				sendLog("SSL/TLS verified: " + res.Protocol + " (" + strconv.Itoa(res.DaysLeft) + " days left)")
			}
			sendLog("SSL/TLS analysis complete for " + target)
			sendDone("ssl")
		}()
	}

	if cfg.HTTP && h.AppConfig.EnableHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Inspecting HTTP response from " + httpTarget)
			res := service.GetHTTPInfo(ctx, httpTarget)
			send("http", res)
			if res.Status != "" {
				sendLog("HTTP status: " + res.Status + " (" + strconv.FormatInt(res.ResponseTime, 10) + "ms)")
			}
			sendLog("HTTP inspection finished for " + target)
			sendDone("http")
		}()
	}

	if cfg.Geo && h.AppConfig.EnableGeo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Looking up local GeoIP location data for " + target)
			g, err := service.GetGeoInfo(ctx, target)
			if err != nil {
				send("geo", map[string]string{"error": err.Error()})
				sendLog("Geolocation lookup failed: " + err.Error())
			} else {
				send("geo", g)
				sendLog("Geolocation data updated for " + target)
			}
			sendDone("geo")
		}()
	}

	if cfg.Ports != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireService() {
				return
			}
			defer releaseService()
			sendLog("Starting port scan on " + target)
			portList, parseErr := service.ParsePortSpec(cfg.Ports, h.scanOptions.MaxPorts)
			if parseErr != nil {
				send("portscan", map[string]string{"error": parseErr.Error()})
				sendLog("Port scan rejected: " + parseErr.Error())
				sendDone("portscan")
				return
			}

			results := make(map[int]string)
			var pmu sync.Mutex
			scanResult := service.ScanPortsStreamWithOptions(ctx, target, portList, h.scanOptions, func(port int, banner string, err error) {
				if err == nil {
					pmu.Lock()
					results[port] = banner
					// Create a copy for sending to avoid race condition during Marshal
					msgData := make(map[int]string)
					for k, v := range results {
						msgData[k] = v
					}
					pmu.Unlock()
					send("portscan", service.ScanResult{Open: msgData})
					sendLog("Port " + strconv.Itoa(port) + " is OPEN")
				}
			})
			send("portscan", scanResult)
			sendLog("Port scan completed for " + target)
			sendDone("portscan")
		}()
	}

	wg.Wait()
	sendLog("All tasks completed for " + target)

	msg := WSMessage{Type: "all_done", RequestID: requestID, Target: cardTarget}
	b, _ := json.Marshal(msg)
	_ = writer.write(websocket.TextMessage, b)
}
