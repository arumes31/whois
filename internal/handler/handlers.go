package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"whois/internal/config"
	"whois/internal/model"
	"whois/internal/service"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	maxBulkUploadBytes = 2 * 1024 * 1024
	maxQueryTargets    = 25
	sessionTTL         = 12 * time.Hour
	defaultMaxWSConns  = 128
	defaultMaxWSPerIP  = 8
)

func generateSessionToken(secretKey string) (string, error) {
	if secretKey == "" {
		return "", fmt.Errorf("session secret is empty")
	}
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("generate session entropy: %w", err)
	}
	entropyHex := hex.EncodeToString(entropy)
	issuedAt := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	payload := entropyHex + "." + issuedAt

	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	return payload + "." + signature, nil
}

func validateSessionToken(token, secretKey string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || secretKey == "" {
		return false
	}
	issuedAtUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	issuedAt := time.Unix(issuedAtUnix, 0)
	now := time.Now()
	if issuedAt.After(now.Add(time.Minute)) || now.Sub(issuedAt) > sessionTTL {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSignature)) == 1
}

type Handler struct {
	Storage     *storage.Storage
	DNS         *service.DNSService
	AppConfig   *config.Config
	Upgrader    websocket.Upgrader
	targetSem   chan struct{}
	serviceSem  chan struct{}
	scanOptions service.ScanOptions
	wsConnMu    sync.Mutex
	wsConns     map[*websocket.Conn]struct{}
	wsActive    int
	wsByIP      map[string]int
	maxWSConns  int
	maxWSPerIP  int
	wsWG        sync.WaitGroup
	wsClosing   bool
}

func NewHandler(storage *storage.Storage, cfg *config.Config) *Handler {
	targetConcurrency := cfg.MaxTargetConcurrency
	if targetConcurrency < 1 {
		targetConcurrency = 4
	}
	serviceConcurrency := cfg.MaxServiceConcurrency
	if serviceConcurrency < 1 {
		serviceConcurrency = 12
	}
	scanConcurrency := cfg.PortScanConcurrency
	if scanConcurrency < 1 {
		scanConcurrency = 32
	}
	maxScanPorts := cfg.PortScanMaxPorts
	if maxScanPorts < 1 {
		maxScanPorts = 1024
	}
	maxWSConns := cfg.MaxWSConnections
	if maxWSConns < 1 {
		maxWSConns = defaultMaxWSConns
	}
	maxWSPerIP := cfg.MaxWSConnectionsPerIP
	if maxWSPerIP < 1 {
		maxWSPerIP = defaultMaxWSPerIP
	}
	if maxWSPerIP > maxWSConns {
		maxWSPerIP = maxWSConns
	}
	dnsService := service.NewDNSService(cfg.DNSServers, cfg.BootstrapDNS)
	dnsService.SetMaxAttempts(cfg.DNSMaxAttempts)
	h := &Handler{
		Storage:     storage,
		DNS:         dnsService,
		AppConfig:   cfg,
		targetSem:   make(chan struct{}, targetConcurrency),
		serviceSem:  make(chan struct{}, serviceConcurrency),
		scanOptions: service.ScanOptions{Concurrency: scanConcurrency, MaxPorts: maxScanPorts, ConnectTimeout: 2 * time.Second, BannerTimeout: time.Second},
		wsConns:     make(map[*websocket.Conn]struct{}),
		wsByIP:      make(map[string]int),
		maxWSConns:  maxWSConns,
		maxWSPerIP:  maxWSPerIP,
	}

	h.Upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: 5 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return websocketOriginAllowed(r, cfg)
		},
		Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
			utils.Log.Warn("websocket upgrade rejected",
				utils.Field("status", status),
				utils.Field("reason", reason.Error()),
				utils.Field("uri", r.URL.Path),
			)
			// Gorilla delegates the complete error response to this callback.
			// Keep the useful server-side reason in structured logs, but expose
			// only the standard status text to untrusted clients.
			http.Error(w, http.StatusText(status), status)
		},
	}

	return h
}

type originAddress struct {
	scheme string
	host   string
	port   string
}

func websocketOriginAllowed(r *http.Request, cfg *config.Config) bool {
	if cfg.SkipOriginCheck {
		return true
	}

	originValue := strings.TrimSpace(r.Header.Get("Origin"))
	if originValue == "" {
		// Non-browser clients do not always send Origin. Browsers do, which is
		// the trust boundary this check protects.
		return true
	}

	expected, err := expectedWebSocketOrigin(r, cfg)
	if err != nil {
		return false
	}
	origin, err := parseOrigin(originValue)
	if err != nil {
		return false
	}

	if origin == expected {
		return true
	}

	allowedDomain := strings.ToLower(strings.Trim(strings.TrimSpace(cfg.AllowedDomain), "."))
	hostAllowed := origin.host == allowedDomain || strings.HasSuffix(origin.host, "."+allowedDomain)
	if allowedDomain != "" && hostAllowed && origin.scheme == expected.scheme && origin.port == expected.port {
		return true
	}

	utils.Log.Warn("websocket origin rejected",
		utils.Field("origin", originValue),
		utils.Field("request_host", r.Host),
		utils.Field("allowed_domain", cfg.AllowedDomain),
	)
	return false
}

func expectedWebSocketOrigin(r *http.Request, cfg *config.Config) (originAddress, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	authority := r.Host

	if requestFromTrustedProxy(r, cfg) {
		if forwardedScheme := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); forwardedScheme != "" {
			scheme = strings.ToLower(forwardedScheme)
		}
		if forwardedHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			authority = forwardedHost
		}
	}

	return parseOrigin(scheme + "://" + authority)
}

func parseOrigin(value string) (originAddress, error) {
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return originAddress{}, fmt.Errorf("invalid websocket origin")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return originAddress{}, fmt.Errorf("unsupported websocket origin scheme")
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	return originAddress{
		scheme: scheme,
		host:   strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")),
		port:   port,
	}, nil
}

func firstForwardedValue(value string) string {
	first, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(first)
}

func requestFromTrustedProxy(r *http.Request, cfg *config.Config) bool {
	if !cfg.TrustProxy && !cfg.UseCloudflare {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.Trim(r.RemoteAddr, "[]")
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}

	for _, entry := range strings.Split(cfg.TrustedProxies, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if trustedIP := net.ParseIP(entry); trustedIP != nil && trustedIP.Equal(peer) {
			return true
		}
		if _, network, parseErr := net.ParseCIDR(entry); parseErr == nil && network.Contains(peer) {
			return true
		}
	}
	return false
}

// Close terminates hijacked WebSocket connections that net/http shutdown does
// not own, allowing their query contexts and goroutines to unwind.
func (h *Handler) Close() {
	h.wsConnMu.Lock()
	h.wsClosing = true
	connections := make([]*websocket.Conn, 0, len(h.wsConns))
	for connection := range h.wsConns {
		connections = append(connections, connection)
	}
	h.wsConnMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

// WaitForClose waits for all WebSocket handlers and their query goroutines to
// finish after Close has signaled the hijacked connections.
func (h *Handler) WaitForClose(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.wsWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// === Middleware ===
func (h *Handler) LoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := c.Cookie("session_id")
		if sess == nil || sess.Value == "" || !validateSessionToken(sess.Value, os.Getenv("SECRET_KEY")) {
			return c.Redirect(http.StatusFound, "/login?next="+c.Request().URL.Path)
		}
		return next(c)
	}
}

func (h *Handler) secureCookie(c echo.Context) bool {
	if h.AppConfig.SessionCookieSecure || c.Request().TLS != nil {
		return true
	}
	if !requestFromTrustedProxy(c.Request(), h.AppConfig) {
		return false
	}
	return strings.EqualFold(firstForwardedValue(c.Request().Header.Get("X-Forwarded-Proto")), "https")
}

// === Routes ===

func (h *Handler) Index(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)
	stats, _ := h.Storage.GetSystemStats(c.Request().Context())
	viewConfig := h.templateConfig()

	if c.Request().Method == http.MethodPost {
		ipsDomains := c.FormValue("ips_and_domains")
		exportType := c.FormValue("export")

		whoisEnabled := c.FormValue("whois") != "" && h.AppConfig.EnableWhois
		dnsEnabled := c.FormValue("dns") != "" && h.AppConfig.EnableDNS
		ctEnabled := c.FormValue("ct") != "" && h.AppConfig.EnableCT
		sslEnabled := c.FormValue("ssl") != "" && h.AppConfig.EnableSSL
		httpEnabled := c.FormValue("http") != "" && h.AppConfig.EnableHTTP
		geoEnabled := c.FormValue("geo") != "" && viewConfig.EnableGeo

		items := strings.FieldsFunc(ipsDomains, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
		if len(items) > maxQueryTargets {
			return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "too many targets; maximum is 25")
		}
		var cleanedItems []string
		seenItems := make(map[string]struct{})
		for _, item := range items {
			trimmed := strings.TrimSpace(item)
			info := utils.NormalizeTarget(trimmed)
			if info.Valid && info.Networkable && utils.IsValidTarget(info.Normalized) {
				identity := info.Scheme + "|" + info.Normalized
				if _, exists := seenItems[identity]; !exists {
					if len(cleanedItems) >= maxQueryTargets {
						return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "too many targets; maximum is 25")
					}
					cleanedItems = append(cleanedItems, trimmed)
					seenItems[identity] = struct{}{}
				}
			}
		}

		results := make(map[string]model.QueryResult)
		var mu sync.Mutex
		var wg sync.WaitGroup

		for _, item := range cleanedItems {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				select {
				case <-c.Request().Context().Done():
					return
				case h.targetSem <- struct{}{}:
					defer func() { <-h.targetSem }()
				}
				res := h.queryItem(c.Request().Context(), target, dnsEnabled, whoisEnabled, ctEnabled, sslEnabled, httpEnabled, geoEnabled)
				mu.Lock()
				results[target] = res
				mu.Unlock()
			}(item)
		}
		wg.Wait()

		if exportType == "csv" {
			return h.exportCSV(c, results)
		}
		if exportType == "json" {
			return c.JSON(http.StatusOK, results)
		}

		return c.Render(http.StatusOK, "index.html", map[string]interface{}{
			"results":       results,
			"ordered_items": cleanedItems,
			"whois_enabled": whoisEnabled,
			"dns_enabled":   dnsEnabled,
			"ct_enabled":    ctEnabled,
			"ssl_enabled":   sslEnabled,
			"http_enabled":  httpEnabled,
			"geo_enabled":   geoEnabled,
			"real_ip":       realIP,
			"auto_expand":   true,
			"stats":         stats,
			"config":        viewConfig,
			"geo_available": viewConfig.EnableGeo,
			"mac_available": service.MACDatabaseAvailable(),
			"current_path":  c.Request().URL.Path,
			"csrf":          c.Get(middleware.DefaultCSRFConfig.ContextKey),
		})
	}

	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"auto_expand":   false,
		"real_ip":       realIP,
		"stats":         stats,
		"config":        viewConfig,
		"geo_available": viewConfig.EnableGeo,
		"mac_available": service.MACDatabaseAvailable(),
		"current_path":  c.Request().URL.Path,
		"csrf":          c.Get(middleware.DefaultCSRFConfig.ContextKey),
	})
}

func (h *Handler) templateConfig() *config.Config {
	viewConfig := *h.AppConfig
	viewConfig.EnableGeo = viewConfig.EnableGeo && service.GeoDBAvailable()
	return &viewConfig
}

func (h *Handler) recordDNSHistory(ctx context.Context, target string, result interface{}, notify func(string)) {
	if err := h.Storage.AddDNSHistory(ctx, target, result); err != nil {
		utils.Log.Warn("failed to persist DNS history",
			utils.Field("target", target),
			utils.Field("error", err.Error()),
		)
		if notify == nil {
			return
		}
		if errors.Is(err, storage.ErrDNSHistoryCapacity) {
			notify("DNS history was not saved: retention capacity reached")
			return
		}
		notify("DNS history could not be saved")
	}
}

func (h *Handler) BulkUpload(c echo.Context) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
	}

	if file.Size > maxBulkUploadBytes {
		return c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "File too large (max 2MB)"})
	}

	ext := strings.ToLower(file.Filename)
	if !strings.HasSuffix(ext, ".txt") && !strings.HasSuffix(ext, ".csv") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid file type (only .txt, .csv allowed)"})
	}

	src, err := file.Open()
	if err != nil {
		return err
	}
	defer func() {
		_ = src.Close()
	}()

	targets := make([]string, 0, maxQueryTargets)
	seen := make(map[string]struct{}, maxQueryTargets)
	addTarget := func(candidate string) bool {
		trimmed := strings.TrimSpace(candidate)
		info := utils.NormalizeTarget(trimmed)
		if !info.Valid || !info.Networkable || !utils.IsValidTarget(trimmed) {
			return true
		}
		identity := info.Scheme + "|" + info.Normalized
		if _, exists := seen[identity]; exists {
			return true
		}
		if len(targets) >= maxQueryTargets {
			return false
		}
		seen[identity] = struct{}{}
		targets = append(targets, trimmed)
		return true
	}
	if strings.HasSuffix(ext, ".csv") {
		r := csv.NewReader(src)
		records, err := r.ReadAll()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid CSV format"})
		}
		for _, record := range records {
			for _, field := range record {
				if !addTarget(field) {
					return c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "Too many targets (max 25)"})
				}
			}
		}
	} else {
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, src); err != nil {
			return err
		}
		lines := strings.Split(buf.String(), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				if !addTarget(part) {
					return c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "Too many targets (max 25)"})
				}
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"targets": targets,
		"count":   len(targets),
	})
}

func (h *Handler) exportCSV(c echo.Context, results map[string]model.QueryResult) error {
	c.Response().Header().Set(echo.HeaderContentType, "text/csv")
	c.Response().Header().Set(echo.HeaderContentDisposition, "attachment;filename=results.csv")
	c.Response().WriteHeader(http.StatusOK)

	writer := csv.NewWriter(c.Response().Writer)
	if err := writer.Write([]string{"Item", "Type", "Data"}); err != nil {
		return err
	}

	items := make([]string, 0, len(results))
	for item := range results {
		items = append(items, item)
	}
	sort.Strings(items)
	for _, item := range items {
		data := results[item]
		rows := []struct {
			name string
			data interface{}
		}{
			{"Target", data.Target}, {"WHOIS", data.Whois}, {"DNS", data.DNS},
			{"CT", data.CT}, {"SSL", data.SSL}, {"HTTP", data.HTTP}, {"Geo", data.Geo},
		}
		for _, row := range rows {
			if row.data == nil {
				continue
			}
			var value string
			if text, ok := row.data.(string); ok {
				value = text
			} else {
				encoded, err := json.Marshal(row.data)
				if err != nil {
					return fmt.Errorf("encode %s result: %w", row.name, err)
				}
				value = string(encoded)
			}
			if err := writer.Write([]string{spreadsheetSafe(item), row.name, spreadsheetSafe(value)}); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
}

func spreadsheetSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

func (h *Handler) queryItem(ctx context.Context, item string, dnsEnabled, whoisEnabled, ctEnabled, sslEnabled, httpEnabled, geoEnabled bool) model.QueryResult {
	cacheKey := fmt.Sprintf("query:%s:%v:%v:%v:%v:%v:%v", item, dnsEnabled, whoisEnabled, ctEnabled, sslEnabled, httpEnabled, geoEnabled)

	if cached, err := h.Storage.GetCache(ctx, cacheKey); err == nil {
		var res model.QueryResult
		if json.Unmarshal([]byte(cached), &res) == nil {
			return res
		}
	}

	targetInfo := utils.EnrichTarget(ctx, item)
	res := model.QueryResult{Target: targetInfo}
	isIP := targetInfo.Kind == model.TargetKindIPv4 || targetInfo.Kind == model.TargetKindIPv6
	hostTarget := targetInfo.Host
	endpointTarget := targetInfo.Normalized
	httpTarget := item
	cacheable := true
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case h.serviceSem <- struct{}{}:
				defer func() { <-h.serviceSem }()
			}
			fn()
		}()
	}

	if whoisEnabled {
		run(func() {
			w := service.Whois(ctx, hostTarget)
			res.Whois = w
		})
	}

	if dnsEnabled {
		run(func() {
			d, err := h.DNS.Lookup(ctx, hostTarget, isIP)
			if err != nil {
				res.DNS = model.DNSResult{"error": err.Error()}
				cacheable = false
				return
			}
			res.DNS = d
			h.recordDNSHistory(ctx, hostTarget, d, nil)
		})
	}

	if ctEnabled {
		if targetInfo.Kind == model.TargetKindDomain {
			run(func() {
				ctCacheKey := "ct:" + hostTarget
				if cached, err := h.Storage.GetCache(ctx, ctCacheKey); err == nil {
					var ctRes interface{}
					if json.Unmarshal([]byte(cached), &ctRes) == nil {
						res.CT = ctRes
						return
					}
				}

				c, err := service.FetchCTSubdomains(ctx, hostTarget)
				if err != nil {
					res.CT = map[string]string{"error": err.Error()}
				} else {
					res.CT = c
					_ = h.Storage.SetCache(ctx, ctCacheKey, c, 1*time.Hour)
				}
			})
		} else {
			res.CT = map[string]string{"error": "CT not applicable to IP"}
		}
	}

	if sslEnabled {
		run(func() {
			res.SSL = service.GetSSLInfo(ctx, endpointTarget)
		})
	}

	if httpEnabled {
		run(func() {
			res.HTTP = service.GetHTTPInfo(ctx, httpTarget)
		})
	}

	if geoEnabled {
		run(func() {
			g, err := service.GetGeoInfo(ctx, hostTarget)
			if err == nil {
				res.Geo = g
			} else {
				res.Geo = map[string]string{"error": err.Error()}
			}
		})
	}

	wg.Wait()
	if ctx.Err() == nil && cacheable {
		_ = h.Storage.SetCache(ctx, cacheKey, res, 10*time.Minute)
	}
	return res
}

func (h *Handler) Scanner(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)
	return c.Render(http.StatusOK, "scanner.html", map[string]interface{}{
		"config":       h.templateConfig(),
		"csrf":         c.Get(middleware.DefaultCSRFConfig.ContextKey),
		"current_path": c.Request().URL.Path,
		"page_title":   "Port Scanner",
		"real_ip":      realIP,
	})
}

func (h *Handler) Scan(c echo.Context) error {
	target := c.FormValue("target")
	if target == "" {
		target = c.RealIP()
	}

	rawPorts := c.FormValue("ports")
	if rawPorts == "" {
		rawPorts = "80,443,22,21,25,3389"
	}

	info := utils.NormalizeTarget(target)
	if !info.Valid || !info.Networkable || !utils.IsValidTarget(info.Normalized) {
		return c.Render(http.StatusBadRequest, "scan_result.html", map[string]interface{}{"target": target, "remote_ip": c.RealIP(), "result": service.ScanResult{Error: []string{"invalid target"}}})
	}
	ports, err := service.ParsePortSpec(rawPorts, h.scanOptions.MaxPorts)
	if err != nil {
		return c.Render(http.StatusBadRequest, "scan_result.html", map[string]interface{}{"target": info.Normalized, "remote_ip": c.RealIP(), "result": service.ScanResult{Error: []string{err.Error()}}})
	}

	res := service.ScanPortsStreamWithOptions(c.Request().Context(), info.Normalized, ports, h.scanOptions, nil)

	return c.Render(http.StatusOK, "scan_result.html", map[string]interface{}{
		"target":    info.Normalized,
		"remote_ip": c.RealIP(),
		"result":    res,
	})
}

func (h *Handler) DNSLookup(c echo.Context) error {
	domain := strings.TrimSpace(c.FormValue("domain"))
	rtype := strings.ToUpper(c.FormValue("type"))
	if rtype == "" {
		rtype = "A"
	}

	targetInfo := utils.NormalizeTarget(domain)
	if !targetInfo.Valid || !targetInfo.Networkable {
		return c.HTML(http.StatusBadRequest, "<div class='alert-err'>Error: invalid DNS target</div>")
	}
	isIP := targetInfo.Kind == model.TargetKindIPv4 || targetInfo.Kind == model.TargetKindIPv6
	results, err := h.DNS.LookupType(c.Request().Context(), targetInfo.Host, rtype, isIP)
	if err != nil {
		return c.HTML(http.StatusBadRequest, fmt.Sprintf("<div class='alert-err'>Error: %v</div>", html.EscapeString(err.Error())))
	}

	if len(results) == 0 {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert-ok'>No %s records found for %s</div>", html.EscapeString(rtype), html.EscapeString(domain)))
	}

	htmlRes := fmt.Sprintf("<div class='dns-type'>%s RECORDS FOR %s</div><div class='dns-values'>", html.EscapeString(rtype), html.EscapeString(domain))
	for _, res := range results {
		htmlRes += fmt.Sprintf("<div class='clickable-record'>%s</div>", html.EscapeString(res))
	}
	htmlRes += "</div>"

	return c.HTML(http.StatusOK, htmlRes)
}

func (h *Handler) MacLookup(c echo.Context) error {
	mac := c.FormValue("mac")
	ctx := c.Request().Context()
	cacheKey := "mac:" + mac

	if cached, err := h.Storage.GetCache(ctx, cacheKey); err == nil {
		var vendor string
		if json.Unmarshal([]byte(cached), &vendor) == nil {
			return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert-ok'>MAC vendor for %s ▸ %s</div>", html.EscapeString(mac), html.EscapeString(vendor)))
		}
	}

	vendor, err := service.LookupMacVendor(ctx, mac)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert-err'>Error: %v</div>", html.EscapeString(err.Error())))
	}

	_ = h.Storage.SetCache(ctx, cacheKey, vendor, 24*time.Hour)
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert-ok'>MAC vendor for %s ▸ %s</div>", html.EscapeString(mac), html.EscapeString(vendor)))
}

func (h *Handler) Login(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)
	next := c.QueryParam("next")
	if c.Request().Method == http.MethodPost {
		next = c.FormValue("next")
	}
	if next != "/config" {
		next = "/config"
	}
	pageData := map[string]interface{}{
		"config":       h.templateConfig(),
		"csrf":         c.Get(middleware.DefaultCSRFConfig.ContextKey),
		"current_path": c.Request().URL.Path,
		"next":         next,
		"page_title":   "Configuration Access",
		"real_ip":      realIP,
	}

	if c.Request().Method == http.MethodPost {
		user := c.FormValue("username")
		pass := c.FormValue("password")

		envUser := os.Getenv("CONFIG_USER")
		envPass := os.Getenv("CONFIG_PASS")

		if user != "" && envUser != "" && pass != "" && envPass != "" &&
			subtle.ConstantTimeCompare([]byte(user), []byte(envUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(envPass)) == 1 {
			token, err := generateSessionToken(os.Getenv("SECRET_KEY"))
			if err != nil {
				utils.Log.Error("failed to generate config session", utils.Field("error", err.Error()))
				return echo.NewHTTPError(http.StatusInternalServerError, "Unable to create session")
			}
			// #nosec G124 -- secureCookie enforces Secure in production and for HTTPS requests.
			c.SetCookie(&http.Cookie{
				Name:     "session_id",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   h.secureCookie(c),
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(sessionTTL.Seconds()),
				Expires:  time.Now().Add(sessionTTL),
			})
			return c.Redirect(http.StatusFound, next)
		}
		pageData["error"] = "Invalid credentials"
		return c.Render(http.StatusOK, "login.html", pageData)
	}
	return c.Render(http.StatusOK, "login.html", pageData)
}

func (h *Handler) Config(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)

	ctx := c.Request().Context()
	if c.Request().Method == http.MethodPost {
		action := c.FormValue("action")
		item := strings.TrimSpace(c.FormValue("item"))

		var err error
		switch action {
		case "add":
			target := utils.NormalizeTarget(item)
			if !target.Valid || !target.Networkable || target.Host == "" || !utils.IsValidTarget(target.Host) {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid monitored target")
			}
			_, err = h.Storage.AddMonitoredItemIfAbsent(ctx, target.Host)
		case "remove":
			if item == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid monitored target")
			}
			err = h.Storage.RemoveMonitoredItem(ctx, item)
		default:
			return echo.NewHTTPError(http.StatusBadRequest, "invalid monitoring action")
		}
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "unable to update monitored targets").SetInternal(err)
		}
		return c.Redirect(http.StatusFound, "/config")
	}

	items, err := h.Storage.GetMonitoredItems(ctx)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "unable to load monitored targets").SetInternal(err)
	}
	viewConfig := h.templateConfig()
	return c.Render(http.StatusOK, "config.html", map[string]interface{}{
		"config":        viewConfig,
		"csrf":          c.Get(middleware.DefaultCSRFConfig.ContextKey),
		"current_path":  c.Request().URL.Path,
		"geo_available": viewConfig.EnableGeo,
		"monitored":     items,
		"page_title":    "Monitoring Configuration",
		"real_ip":       realIP,
	})
}

func (h *Handler) Logout(c echo.Context) error {
	// #nosec G124 -- secureCookie enforces Secure in production and for HTTPS requests.
	c.SetCookie(&http.Cookie{
		Name:     "session_id",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookie(c),
		SameSite: http.SameSiteLaxMode,
	})
	return c.Redirect(http.StatusFound, "/")
}

func (h *Handler) GetHistory(c echo.Context) error {
	// DNS answers are public data and the dashboard consumes this endpoint
	// without a configuration session. Keep it public, but only accept one
	// normalized DNS target and apply route-specific rate limiting in NewServer.
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	c.Response().Header().Set("X-Robots-Tag", "noindex, nofollow")
	item := strings.TrimSpace(c.QueryParam("item"))
	if item == "" {
		item = strings.TrimSpace(c.Param("item"))
	}
	if len(item) > 512 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid DNS history target"})
	}
	target := utils.NormalizeTarget(item)
	if !target.Valid || target.Host == "" || (target.Kind != model.TargetKindDomain && target.Kind != model.TargetKindIPv4 && target.Kind != model.TargetKindIPv6) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid DNS history target"})
	}
	item = target.Host
	entries, diffs, err := h.Storage.GetHistoryWithDiffs(c.Request().Context(), item)
	if err != nil {
		utils.Log.Error("failed to load DNS history", utils.Field("item", item), utils.Field("error", err.Error()))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "unable to load DNS history"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"entries": entries,
		"diffs":   diffs,
	})
}

func (h *Handler) SystemStats(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	stats, err := h.Storage.GetSystemStats(c.Request().Context())
	if err != nil {
		utils.Log.Error("failed to load system stats", utils.Field("error", err.Error()))
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":          "ok",
		"monitored_count": stats.MonitoredCount,
		"history_count":   stats.HistoryCount,
		"geo_available":   service.GeoDBAvailable(),
		"mac_available":   service.MACDatabaseAvailable(),
	})
}

func (h *Handler) Metrics(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
		clientIP := utils.ExtractIP(c, pCfg)

		if !utils.IsTrustedIP(clientIP, h.AppConfig.TrustedIPs) {
			utils.Log.Warn("untrusted metrics access attempt", utils.Field("ip", clientIP))
			return c.NoContent(http.StatusForbidden)
		}

		// Throttling / Slowdown logic
		ctx := c.Request().Context()
		key := "metrics_throttle:" + clientIP

		count, err := h.Storage.Client.Incr(ctx, key).Result()
		if err == nil {
			if count == 1 {
				h.Storage.Client.Expire(ctx, key, time.Minute)
			}

			// If more than 5 requests in a minute, start slowing down
			if count > 5 {
				delay := time.Duration(count-5) * 500 * time.Millisecond
				if delay > 10*time.Second {
					delay = 10 * time.Second
				}
				utils.Log.Warn("throttling metrics access", utils.Field("ip", clientIP), utils.Field("count", count), utils.Field("delay", delay))

				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		return next(c)
	}
}

func (h *Handler) Health(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()

	if err := h.Storage.Client.Ping(ctx).Err(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"status": "error",
			"redis":  "unavailable",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status": "ok",
		"redis":  "connected",
	})
}

func (h *Handler) Liveness(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) UpdateGeoDB(c echo.Context) error {
	if err := service.ManualUpdateGeoDB(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "GeoIP database updated successfully"})
}

func (h *Handler) Robots(c echo.Context) error {
	content := "User-agent: *\nDisallow: /"
	if h.AppConfig.SEOEnabled {
		content = "User-agent: *\nAllow: /\nDisallow: /config\nDisallow: /metrics\nDisallow: /login"
	}
	return c.String(http.StatusOK, content)
}
