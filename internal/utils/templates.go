package utils

import (
	"html/template"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"whois/internal/model"

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

var (
	allowPrivateIPs   int32
	allowLoopbackIPs  int32
	allowLinkLocalIPs int32
)

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

func SetAllowLoopbackIPs(v bool) {
	if v {
		atomic.StoreInt32(&allowLoopbackIPs, 1)
	} else {
		atomic.StoreInt32(&allowLoopbackIPs, 0)
	}
}

func GetAllowLoopbackIPs() bool {
	return atomic.LoadInt32(&allowLoopbackIPs) == 1
}

func SetAllowLinkLocalIPs(v bool) {
	if v {
		atomic.StoreInt32(&allowLinkLocalIPs, 1)
	} else {
		atomic.StoreInt32(&allowLinkLocalIPs, 0)
	}
}

func addressAllowed(meta model.IPMetadata) bool {
	if meta.IsMulticast || meta.IsUnspecified || meta.IsDocumentation || meta.IsCGNAT || meta.IsReserved {
		return false
	}
	if meta.IsLoopback {
		return atomic.LoadInt32(&allowLoopbackIPs) == 1
	}
	if meta.IsLinkLocal {
		return atomic.LoadInt32(&allowLinkLocalIPs) == 1
	}
	return !meta.IsPrivate || GetAllowPrivateIPs()
}

// IsPublicIP reports whether ip is safe for infrastructure-selected outbound
// connections. Unlike user target policy, this deliberately ignores the
// ALLOW_* overrides so remote referrals can never opt into internal networks.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	meta := classifyIP(addr.Unmap())
	return !meta.IsPrivate && !meta.IsLoopback && !meta.IsLinkLocal &&
		!meta.IsMulticast && !meta.IsUnspecified && !meta.IsDocumentation &&
		!meta.IsCGNAT && !meta.IsReserved && !meta.IsBogon
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
	return addressAllowed(meta)
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
	if !cfg.TrustProxy && !cfg.UseCloudflare {
		host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
		if err == nil {
			return host
		}
		return strings.Trim(c.Request().RemoteAddr, "[]")
	}
	// Proxy-aware servers configure Echo's IPExtractor with explicit trusted
	// proxy ranges. RealIP then safely applies that centralized policy.
	return c.RealIP()
}
