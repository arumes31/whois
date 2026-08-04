package utils

import (
	"html/template"
	"io"
	"net"
	"strings"
	"sync/atomic"

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

var allowPrivateIPs int32

func SetAllowPrivateIPs(v bool) {
	if v {
		atomic.StoreInt32(&allowPrivateIPs, 1)
	} else {
		atomic.StoreInt32(&allowPrivateIPs, 0)
	}
}

func GetAllowPrivateIPs() bool {
	return atomic.LoadInt32(&allowPrivateIPs) == 1
}

func IsValidTarget(target string) bool {
	info := NormalizeTarget(target)
	if !info.Valid || !info.Networkable {
		return false
	}
	if len(info.IPs) == 0 {
		return true
	}
	meta := info.IPs[0]
	if meta.IsMulticast || meta.IsUnspecified {
		return false
	}
	return GetAllowPrivateIPs() || !meta.IsBogon
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
