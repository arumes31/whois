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
	}

	h.Upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: 5 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			if cfg.SkipOriginCheck {
				return true
			}

			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}

			// Robust host comparison: strip ports if present
			originHost := u.Hostname()
			requestHost := r.Host
			if host, _, err := net.SplitHostPort(requestHost); err == nil {
				requestHost = host
			}

			// Also check X-Forwarded-Host if present (common behind reverse proxies)
			forwardedHost := r.Header.Get("X-Forwarded-Host")
			if forwardedHost != "" {
				if host, _, err := net.SplitHostPort(forwardedHost); err == nil {
					forwardedHost = host
				}
			}

			// Cloudflare support: detect CF headers
			cfIP := r.Header.Get("CF-Connecting-IP")
			cfRay := r.Header.Get("CF-Ray")

			utils.Log.Info("websocket origin check",
				utils.Field("origin", origin),
				utils.Field("origin_hostname", originHost),
				utils.Field("request_host", r.Host),
				utils.Field("request_hostname", requestHost),
				utils.Field("forwarded_host", forwardedHost),
				utils.Field("cf_ip", cfIP),
				utils.Field("cf_ray", cfRay),
				utils.Field("use_cloudflare", cfg.UseCloudflare),
				utils.Field("allowed_domain", cfg.AllowedDomain),
			)

			// Allow if hosts match exactly
			if originHost == requestHost || (forwardedHost != "" && originHost == forwardedHost) {
				return true
			}

			// If Cloudflare is enabled and headers are present, trust the origin
			// if it matches the host or is a subdomain of the allowed domain.
			if cfg.UseCloudflare && cfIP != "" {
				if originHost == requestHost || originHost == forwardedHost {
					return true
				}
			}

			// Fallback: Allow localhost/127.0.0.1 for development
			if requestHost == "localhost" || requestHost == "127.0.0.1" || originHost == "localhost" || originHost == "127.0.0.1" {
				return true
			}

			// If we are on a subdomain of the allowed domain
			if cfg.AllowedDomain != "" {
				if strings.HasSuffix(originHost, "."+cfg.AllowedDomain) || originHost == cfg.AllowedDomain {
					return true
				}
			}

			utils.Log.Warn("websocket origin rejected",
				utils.Field("origin", origin),
				utils.Field("request_host", r.Host),
				utils.Field("allowed_domain", cfg.AllowedDomain),
			)
			return false
		},
		Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
			utils.Log.Error("websocket upgrade error",
				utils.Field("status", status),
				utils.Field("reason", reason.Error()),
				utils.Field("uri", r.URL.Path),
			)
		},
	}

	return h
}

// Close terminates hijacked WebSocket connections that net/http shutdown does
// not own, allowing their query contexts and goroutines to unwind.
func (h *Handler) Close() {
	h.wsConnMu.Lock()
	connections := make([]*websocket.Conn, 0, len(h.wsConns))
	for connection := range h.wsConns {
		connections = append(connections, connection)
	}
	h.wsConnMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
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

// === Routes ===

func (h *Handler) Index(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)
	stats, _ := h.Storage.GetSystemStats(c.Request().Context())

	if c.Request().Method == http.MethodPost {
		ipsDomains := c.FormValue("ips_and_domains")
		exportType := c.FormValue("export")

		whoisEnabled := c.FormValue("whois") != "" && h.AppConfig.EnableWhois
		dnsEnabled := c.FormValue("dns") != "" && h.AppConfig.EnableDNS
		ctEnabled := c.FormValue("ct") != "" && h.AppConfig.EnableCT
		sslEnabled := c.FormValue("ssl") != "" && h.AppConfig.EnableSSL
		httpEnabled := c.FormValue("http") != "" && h.AppConfig.EnableHTTP
		geoEnabled := c.FormValue("geo") != "" && h.AppConfig.EnableGeo

		items := strings.FieldsFunc(ipsDomains, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
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
			"config":        h.AppConfig,
			"current_path":  c.Request().URL.Path,
			"csrf":          c.Get(middleware.DefaultCSRFConfig.ContextKey),
		})
	}

	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"auto_expand":  false,
		"real_ip":      realIP,
		"stats":        stats,
		"config":       h.AppConfig,
		"current_path": c.Request().URL.Path,
		"csrf":         c.Get(middleware.DefaultCSRFConfig.ContextKey),
	})
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

	var targets []string
	if strings.HasSuffix(ext, ".csv") {
		r := csv.NewReader(src)
		records, err := r.ReadAll()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid CSV format"})
		}
		for _, record := range records {
			for _, field := range record {
				trimmed := strings.TrimSpace(field)
				if utils.IsValidTarget(trimmed) {
					targets = append(targets, trimmed)
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
				trimmed := strings.TrimSpace(part)
				if utils.IsValidTarget(trimmed) {
					targets = append(targets, trimmed)
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
			if err == nil {
				res.DNS = d
				_ = h.Storage.AddDNSHistory(ctx, hostTarget, d)
			}
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
	_ = h.Storage.SetCache(ctx, cacheKey, res, 10*time.Minute)
	return res
}

func (h *Handler) Scanner(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)
	return c.Render(http.StatusOK, "scanner.html", map[string]interface{}{
		"real_ip": realIP,
		"config":  h.AppConfig,
		"csrf":    c.Get(middleware.DefaultCSRFConfig.ContextKey),
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
		return c.HTML(http.StatusBadRequest, "<div class='alert alert-danger'>Error: invalid DNS target</div>")
	}
	isIP := targetInfo.Kind == model.TargetKindIPv4 || targetInfo.Kind == model.TargetKindIPv6
	results, err := h.DNS.LookupType(c.Request().Context(), targetInfo.Host, rtype, isIP)
	if err != nil {
		return c.HTML(http.StatusBadRequest, fmt.Sprintf("<div class='alert alert-danger'>Error: %v</div>", html.EscapeString(err.Error())))
	}

	if len(results) == 0 {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-warning'>No %s records found for %s</div>", html.EscapeString(rtype), html.EscapeString(domain)))
	}

	htmlRes := fmt.Sprintf("<div class='glass-panel p-3 border-nordic'><strong class='text-nordic-blue d-block mb-2'>%s RECORDS FOR %s</strong>", html.EscapeString(rtype), html.EscapeString(domain))
	for _, res := range results {
		htmlRes += fmt.Sprintf("<div class='clickable-record p-1 small border-bottom border-secondary border-opacity-10' onclick='copyToClipboard(this)'>%s</div>", html.EscapeString(res))
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
			return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>MAC Vendor for %s:</strong><br>%s</div>", html.EscapeString(mac), html.EscapeString(vendor)))
		}
	}

	vendor, err := service.LookupMacVendor(ctx, mac)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-danger'>Error: %v</div>", html.EscapeString(err.Error())))
	}

	_ = h.Storage.SetCache(ctx, cacheKey, vendor, 24*time.Hour)
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>MAC Vendor for %s:</strong><br>%s</div>", html.EscapeString(mac), html.EscapeString(vendor)))
}

func (h *Handler) Login(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)

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
			c.SetCookie(&http.Cookie{
				Name:     "session_id",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   true, // Recommended for HTTPS
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(sessionTTL.Seconds()),
				Expires:  time.Now().Add(sessionTTL),
			})
			return c.Redirect(http.StatusFound, "/config")
		}
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get(middleware.DefaultCSRFConfig.ContextKey), "real_ip": realIP})
	}
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get(middleware.DefaultCSRFConfig.ContextKey), "real_ip": realIP})
}

func (h *Handler) Config(c echo.Context) error {
	pCfg := utils.ProxyConfig{TrustProxy: h.AppConfig.TrustProxy, UseCloudflare: h.AppConfig.UseCloudflare}
	realIP := utils.ExtractIP(c, pCfg)

	ctx := c.Request().Context()
	if c.Request().Method == http.MethodPost {
		action := c.FormValue("action")
		item := strings.TrimSpace(c.FormValue("item"))
		if action == "add" && item != "" {
			_ = h.Storage.AddMonitoredItem(ctx, item)
		} else if action == "remove" && item != "" {
			_ = h.Storage.RemoveMonitoredItem(ctx, item)
		}
		return c.Redirect(http.StatusFound, "/config")
	}

	items, _ := h.Storage.GetMonitoredItems(ctx)
	return c.Render(http.StatusOK, "config.html", map[string]interface{}{
		"monitored": items,
		"real_ip":   realIP,
		"csrf":      c.Get(middleware.DefaultCSRFConfig.ContextKey),
	})
}

func (h *Handler) Logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     "session_id",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return c.Redirect(http.StatusFound, "/")
}

func (h *Handler) GetHistory(c echo.Context) error {
	item := c.Param("item")
	entries, diffs, err := h.Storage.GetHistoryWithDiffs(c.Request().Context(), item)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"entries": entries,
		"diffs":   diffs,
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
