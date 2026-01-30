package utils

import (
	"html/template"
	"io"
	"net"
	"strings"

	"github.com/labstack/echo/v4"
)

type TemplateRegistry struct {
	Templates *template.Template
}

func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.Templates.ExecuteTemplate(w, name, data)
}

func IsIP(val interface{}) bool {
	if str, ok := val.(string); ok {
		return net.ParseIP(str) != nil
	}
	return false
}

func IsValidTarget(target string) bool {
	// Support port numbers (e.g. 127.0.0.1:12345 or google.com:443)
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	if ip := net.ParseIP(host); ip != nil {
		// Only block unspecified and multicast. Allow loopback for testing.
		return !ip.IsMulticast() && !ip.IsUnspecified()
	}
	if len(host) > 255 {
		return false
	}
	for _, ch := range host {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '.' && ch != '-' {
			return false
		}
	}
	return strings.Contains(host, ".")
}

func IsValidMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

func IsTrustedIP(remoteAddr string, trustedList string) bool {
	clientIP := net.ParseIP(remoteAddr)
	if clientIP == nil {
		return false
	}

	trustedItems := strings.Split(trustedList, ",")
	for _, item := range trustedItems {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if strings.Contains(item, "/") {
			_, subnet, err := net.ParseCIDR(item)
			if err == nil && subnet.Contains(clientIP) {
				return true
			}
		} else {
			if item == remoteAddr {
				return true
			}
		}
	}
	return false
}

type ProxyConfig struct {
	TrustProxy    bool
	UseCloudflare bool
}

func ExtractIP(c echo.Context, cfg ProxyConfig) string {
	if cfg.UseCloudflare {
		if cfIP := c.Request().Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}
	}

	if cfg.TrustProxy {
		if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}

	return c.RealIP()
}
