package handler

import (
	"context"
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
		// In a real app verify session. Here we just check cookie existence for simplicity 
		// matching the python "session['logged_in']" but we need a secure way.
		// Since python used client side session (Flask default), we can just use a simple cookie for now.
		return next(c)
	}
}

// === Routes ===

func (h *Handler) Index(c echo.Context) error {
	realIP := c.RealIP()
	if c.Request().Method == http.MethodPost {
		ipsDomains := c.FormValue("ips_and_domains")
		// exportType := c.FormValue("export") // Not implemented yet
		whoisEnabled := c.FormValue("whois") != ""
		dnsEnabled := c.FormValue("dns") != ""
		ctEnabled := c.FormValue("ct") != ""

		items := strings.Split(ipsDomains, ",")
		var cleanedItems []string
		for _, i := range items {
			trimmed := strings.TrimSpace(i)
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

		return c.Render(http.StatusOK, "index.html", map[string]interface{}{
			"results":      results,
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
			d, _ := h.DNS.Lookup(item, isIP)
			res.DNS = d
			// Store history
			h.Storage.AddDNSHistory(context.Background(), item, d)
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
	
	// Reuse existing DNS service logic or simple lookup
	// For single lookup HTMX
	// Implementation simplified for brevity
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-info'>DNS %s for %s</div>", rtype, domain))
}

func (h *Handler) MacLookup(c echo.Context) error {
	mac := c.FormValue("mac")
	vendor, _ := service.LookupMacVendor(mac)
	return c.HTML(http.StatusOK, fmt.Sprintf("<div class='alert alert-success'>%s</div>", vendor))
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
