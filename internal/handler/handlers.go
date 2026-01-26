package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"whois/internal/model"
	"whois/internal/service"
	"whois/internal/storage"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	Storage *storage.Storage
	DNS     *service.DNSService
}

func NewHandler(storage *storage.Storage) *Handler {
	return &Handler{
		Storage: storage,
		DNS:     service.NewDNSService(),
	}
}

// === Middleware ===
func (h *Handler) LoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := c.Cookie("session_id")
		if sess == nil || sess.Value == "" {
			return c.Redirect(http.StatusFound, "/login?next="+c.Request().URL.Path)
		}
		return next(c)
	}
}

// === Routes ===

func (h *Handler) Index(c echo.Context) error {
	realIP := c.RealIP()
	if c.Request().Method == http.MethodPost {
		ipsDomains := c.FormValue("ips_and_domains")
		exportType := c.FormValue("export")
		whoisEnabled := c.FormValue("whois") != ""
		dnsEnabled := c.FormValue("dns") != ""
		ctEnabled := c.FormValue("ct") != ""

		items := strings.Split(ipsDomains, ",")
		var cleanedItems []string
		for _, i := range items {
			rimmed := strings.TrimSpace(i)
			if trimmed != "" {
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
				res := h.queryItem(target, dnsEnabled, whoisEnabled, ctEnabled)
				mu.Lock()
				results[target] = res
				mu.Unlock()
			}(item)
		}
		wg.Wait()

		if exportType == "csv" {
			return h.exportCSV(c, results)
		}

		return c.Render(http.StatusOK, "index.html", map[string]interface{}{
			"results":       results,
			"ordered_items": cleanedItems,
			"whois_enabled": whoisEnabled,
			"dns_enabled":   dnsEnabled,
			"ct_enabled":    ctEnabled,
			"real_ip":       realIP,
			"auto_expand":   true,
		})
	}

	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"auto_expand": false,
		"real_ip":     realIP,
	})
}

func (h *Handler) exportCSV(c echo.Context, results map[string]model.QueryResult) error {
	c.Response().Header().Set(echo.HeaderContentType, "text/csv")
	c.Response().Header().Set(echo.HeaderContentDisposition, "attachment;filename=results.csv")
	c.Response().WriteHeader(http.StatusOK)

	writer := csv.NewWriter(c.Response().Writer)
	defer writer.Flush()

	writer.Write([]string{"Item", "Type", "Data"})

	for item, data := range results {
		if data.Whois != nil {
			writer.Write([]string{item, "WHOIS", *data.Whois})
		}
		if data.DNS != nil {
			dnsBytes, _ := json.Marshal(data.DNS)
			writer.Write([]string{item, "DNS", string(dnsBytes)})
		}
		if data.CT != nil {
			ctBytes, _ := json.Marshal(data.CT)
			writer.Write([]string{item, "CT", string(ctBytes)})
		}
	}
	return nil
}

func (h *Handler) queryItem(item string, dnsEnabled, whoisEnabled, ctEnabled bool) model.QueryResult {
	res := model.QueryResult{}
	isIP := net.ParseIP(item) != nil

	var wg sync.WaitGroup

	if whoisEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := service.Whois(item)
			res.Whois = &w
		}()
	}

	if dnsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := h.DNS.Lookup(item, isIP)
			if err == nil {
				res.DNS = d
				h.Storage.AddDNSHistory(context.Background(), item, d)
			}
		}()
	}

	if ctEnabled {
		if !isIP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := service.FetchCTSubdomains(item)
				if err != nil {
					res.CT = map[string]string{"error": err.Error()}
				} else {
					res.CT = c
				}
			}()
		} else {
			res.CT = map[string]string{"error": "CT not applicable to IP"}
		}
	}

	wg.Wait()
	return res
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

	res := service.ScanPorts(target, ports)
	
	return c.Render(http.StatusOK, "scan_result.html", map[string]interface{}{
		"target":    target,
		"remote_ip": c.RealIP(),
		"result":    res,
	})
}

func (h *Handler) DNSLookup(c echo.Context) error {
	domain := c.FormValue("domain")
	rtype := strings.ToUpper(c.FormValue("type"))
	if rtype == "" { rtype = "A" }
	
	isIP := net.ParseIP(domain) != nil
	d, err := h.DNS.Lookup(domain, isIP)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-danger'>Error: %%v</div>", err))
	}

	var results []string
	if val, ok := d[rtype]; ok {
		if list, ok := val.([]string); ok {
			results = list
		}
	}

	if len(results) == 0 {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-warning'>No %%s records found for %%s</div>", rtype, domain))
	}

	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>%%s records for %%s:</strong><pre class='mb-0 mt-2'><code>%%s</code></pre></div>", rtype, domain, strings.Join(results, "\n")))
}

func (h *Handler) MacLookup(c echo.Context) error {
	mac := c.FormValue("mac")
	vendor, err := service.LookupMacVendor(mac)
	if err != nil {
		return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-danger'>Error: %%v</div>", err))
	}
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'><strong>MAC Vendor for %%s:</strong><br>%%s</div>", mac, vendor))
}

func (h *Handler) Login(c echo.Context) error {
	if c.Request().Method == http.MethodPost {
		user := c.FormValue("username")
		pass := c.FormValue("password")
		
		envUser := os.Getenv("CONFIG_USER")
		envPass := os.Getenv("CONFIG_PASS")
		
		if user == envUser && pass == envPass {
			c.SetCookie(&http.Cookie{
				Name: "session_id", 
				Value: "logged_in", 
				Path: "/",
				HttpOnly: true,
			})
			return c.Redirect(http.StatusFound, "/config")
		}
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials"})
	}
	return c.Render(http.StatusOK, "login.html", nil)
}

func (h *Handler) Config(c echo.Context) error {
	ctx := c.Request().Context()
	if c.Request().Method == http.MethodPost {
		action := c.FormValue("action")
		item := strings.TrimSpace(c.FormValue("item"))
		if action == "add" && item != "" {
			h.Storage.AddMonitoredItem(ctx, item)
		} else if action == "remove" && item != "" {
			h.Storage.RemoveMonitoredItem(ctx, item)
		}
		return c.Redirect(http.StatusFound, "/config")
	}
	
	items, _ := h.Storage.GetMonitoredItems(ctx)
	return c.Render(http.StatusOK, "config.html", map[string]interface{}{
		"monitored": items,
	})
}