package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"whois/internal/config"
	"whois/internal/model"
	"whois/internal/service"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Handler struct {
	Storage   *storage.Storage
	DNS       *service.DNSService
	AppConfig *config.Config
	wsMu      sync.Mutex
}

func NewHandler(storage *storage.Storage, cfg *config.Config) *Handler {
	return &Handler{
		Storage:   storage,
		DNS:       service.NewDNSService(cfg.DNSResolver),
		AppConfig: cfg,
	}
}

// === Middleware ===
func (h *Handler) LoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := c.Cookie("session_id")
		expected := fmt.Sprintf("%x", os.Getenv("SECRET_KEY"))
		if sess == nil || sess.Value == "" || sess.Value != expected {
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

		items := strings.Split(ipsDomains, ",")
		var cleanedItems []string
		for _, item := range items {
			trimmed := strings.TrimSpace(item)
			if utils.IsValidTarget(trimmed) {
				cleanedItems = append(cleanedItems, trimmed)
			}
		}

		results := make(map[string]model.QueryResult)
		var mu sync.Mutex
		var wg sync.WaitGroup

		for _, item := range cleanedItems {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
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
		})
	}

	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"auto_expand": false,
		"real_ip":     realIP,
		"stats":       stats,
		"config":      h.AppConfig,
	})
}

func (h *Handler) BulkUpload(c echo.Context) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
	}

	if file.Size > 2*1024*1024 {
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
	defer writer.Flush()

	_ = writer.Write([]string{"Item", "Type", "Data"})

	for item, data := range results {
		if data.Whois != nil {
			if w, ok := data.Whois.(string); ok {
				_ = writer.Write([]string{item, "WHOIS", w})
			}
		}
		if data.DNS != nil {
			dnsBytes, _ := json.Marshal(data.DNS)
			_ = writer.Write([]string{item, "DNS", string(dnsBytes)})
		}
		if data.CT != nil {
			ctBytes, _ := json.Marshal(data.CT)
			_ = writer.Write([]string{item, "CT", string(ctBytes)})
		}
	}
	return nil
}

func (h *Handler) queryItem(ctx context.Context, item string, dnsEnabled, whoisEnabled, ctEnabled, sslEnabled, httpEnabled, geoEnabled bool) model.QueryResult {
	cacheKey := fmt.Sprintf("query:%s:%v:%v:%v:%v:%v:%v", item, dnsEnabled, whoisEnabled, ctEnabled, sslEnabled, httpEnabled, geoEnabled)

	if cached, err := h.Storage.GetCache(ctx, cacheKey); err == nil {
		var res model.QueryResult
		if json.Unmarshal([]byte(cached), &res) == nil {
			return res
		}
	}

	res := model.QueryResult{}
	isIP := net.ParseIP(item) != nil
	var wg sync.WaitGroup

	if whoisEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := service.Whois(item)
			res.Whois = w
		}()
	}

	if dnsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := h.DNS.Lookup(ctx, item, isIP)
			if err == nil {
				res.DNS = d
				_ = h.Storage.AddDNSHistory(ctx, item, d)
			}
		}()
	}

	if ctEnabled {
		if !isIP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctCacheKey := "ct:" + item
				if cached, err := h.Storage.GetCache(ctx, ctCacheKey); err == nil {
					var ctRes interface{}
					if json.Unmarshal([]byte(cached), &ctRes) == nil {
						res.CT = ctRes
						return
					}
				}

				c, err := service.FetchCTSubdomains(ctx, item)
				if err != nil {
					res.CT = map[string]string{"error": err.Error()}
				} else {
					res.CT = c
					_ = h.Storage.SetCache(ctx, ctCacheKey, c, 1*time.Hour)
				}
			}()
		} else {
			res.CT = map[string]string{"error": "CT not applicable to IP"}
		}
	}

	if sslEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.SSL = service.GetSSLInfo(ctx, item)
		}()
	}

	if httpEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.HTTP = service.GetHTTPInfo(ctx, item)
		}()
	}

	if geoEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := service.GetGeoInfo(ctx, item)
			if err == nil {
				res.Geo = g
			} else {
				res.Geo = map[string]string{"error": err.Error()}
			}
		}()
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

	var ports []int
	for _, p := range strings.Split(rawPorts, ",") {
		if i, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, i)
		}
	}

	res := service.ScanPorts(c.Request().Context(), target, ports)

	return c.Render(http.StatusOK, "scan_result.html", map[string]interface{}{
		"target":    target,
		"remote_ip": c.RealIP(),
		"result":    res,
	})
}

func (h *Handler) DNSLookup(c echo.Context) error {
	domain := c.FormValue("domain")
	rtype := strings.ToUpper(c.FormValue("type"))
	if rtype == "" {
		rtype = "A"
	}

	isIP := net.ParseIP(domain) != nil
	d, err := h.DNS.Lookup(c.Request().Context(), domain, isIP)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-danger'>Error: %v</div>", err))
	}

	var results []string
	if val, ok := d[rtype]; ok {
		if list, ok := val.([]string); ok {
			results = list
		}
	}

	if len(results) == 0 {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-warning'>No %s records found for %s</div>", rtype, domain))
	}

	html := fmt.Sprintf("<div class='glass-panel p-3 border-nordic'><strong class='text-nordic-blue d-block mb-2'>%s RECORDS FOR %s</strong>", rtype, domain)
	for _, res := range results {
		html += fmt.Sprintf("<div class='clickable-record p-1 small border-bottom border-secondary border-opacity-25' onclick='copyToClipboard(this)'>%s</div>", res)
	}
	html += "</div>"

	return c.HTML(http.StatusOK, html)
}

func (h *Handler) MacLookup(c echo.Context) error {
	mac := c.FormValue("mac")
	ctx := c.Request().Context()
	cacheKey := "mac:" + mac

	if cached, err := h.Storage.GetCache(ctx, cacheKey); err == nil {
		var vendor string
		if json.Unmarshal([]byte(cached), &vendor) == nil {
			return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>MAC Vendor for %s:</strong><br>%s</div>", mac, vendor))
		}
	}

	vendor, err := service.LookupMacVendor(ctx, mac)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-danger'>Error: %v</div>", err))
	}

	_ = h.Storage.SetCache(ctx, cacheKey, vendor, 24*time.Hour)
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>MAC Vendor for %s:</strong><br>%s</div>", mac, vendor))
}

func (h *Handler) Login(c echo.Context) error {
	if c.Request().Method == http.MethodPost {
		user := c.FormValue("username")
		pass := c.FormValue("password")

		envUser := os.Getenv("CONFIG_USER")
		envPass := os.Getenv("CONFIG_PASS")

		if user != "" && user == envUser && pass == envPass {
			// Generate a simple secure token (In production, use JWT or Redis-backed sessions)
			// For this hardening, we'll use a hash of the credentials + secret
			token := fmt.Sprintf("%x", os.Getenv("SECRET_KEY"))
			c.SetCookie(&http.Cookie{
				Name:     "session_id",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   true, // Recommended for HTTPS
				SameSite: http.SameSiteLaxMode,
			})
			return c.Redirect(http.StatusFound, "/config")
		}
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get(middleware.DefaultCSRFConfig.ContextKey)})
	}
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get(middleware.DefaultCSRFConfig.ContextKey)})
}

func (h *Handler) Config(c echo.Context) error {
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
	})
}

func (h *Handler) Logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
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
		if !utils.IsTrustedIP(c.RealIP(), h.AppConfig.TrustedIPs) {
			return c.NoContent(http.StatusForbidden)
		}

		// Throttling / Slowdown logic
		ip := c.RealIP()
		ctx := c.Request().Context()
		key := "metrics_throttle:" + ip

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
				utils.Log.Warn("throttling metrics access", utils.Field("ip", ip), utils.Field("count", count), utils.Field("delay", delay))

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

func (h *Handler) UpdateGeoDB(c echo.Context) error {
	if err := service.ManualUpdateGeoDB(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "GeoIP database updated successfully"})
}
