package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	RedisHost             string
	RedisPort             string
	Port                  string
	ConfigUser            string
	ConfigPass            string
	SecretKey             string
	TrustedIPs            string
	TrustedProxies        string
	TrustProxy            bool
	UseCloudflare         bool
	EnableGeo             bool
	EnableSSL             bool
	EnableWhois           bool
	EnableDNS             bool
	EnableCT              bool
	EnableHTTP            bool
	AutoUpdateDatabases   bool
	MaxMindLicenseKey     string
	MaxMindAccountID      string
	DNSServers            string
	BootstrapDNS          string
	SEOEnabled            bool
	SEODomain             string
	AllowedDomain         string
	SkipOriginCheck       bool
	AllowPrivateIPs       bool   `json:"allow_private_ips"`
	AllowLoopbackIPs      bool   `json:"allow_loopback_ips"`
	AllowLinkLocalIPs     bool   `json:"allow_link_local_ips"`
	CORSOrigins           string `json:"cors_origins"`
	Environment           string
	AllowDevCors          bool
	MaxTargetConcurrency  int
	MaxServiceConcurrency int
	PortScanConcurrency   int
	PortScanMaxPorts      int
	DNSMaxAttempts        int
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		RedisHost:             getEnv("REDIS_HOST", "localhost"),
		RedisPort:             getEnv("REDIS_PORT", "6379"),
		Port:                  getEnv("PORT", "5000"),
		ConfigUser:            getEnv("CONFIG_USER", "admin"),
		ConfigPass:            getEnv("CONFIG_PASS", "admin"),
		SecretKey:             os.Getenv("SECRET_KEY"),
		TrustedIPs:            getEnv("TRUSTED_IPS", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"),
		TrustedProxies:        getEnv("TRUSTED_PROXIES", "127.0.0.1/32,::1/128"),
		TrustProxy:            getEnvBool("TRUST_PROXY", false),
		UseCloudflare:         getEnvBool("USE_CLOUDFLARE", false),
		EnableGeo:             getEnvBool("ENABLE_GEO", true),
		EnableSSL:             getEnvBool("ENABLE_SSL", true),
		EnableWhois:           getEnvBool("ENABLE_WHOIS", true),
		EnableDNS:             getEnvBool("ENABLE_DNS", true),
		EnableCT:              getEnvBool("ENABLE_CT", true),
		EnableHTTP:            getEnvBool("ENABLE_HTTP", true),
		AutoUpdateDatabases:   getEnvBool("AUTO_UPDATE_DATABASES", false),
		MaxMindLicenseKey:     os.Getenv("MAXMIND_LICENSE_KEY"),
		MaxMindAccountID:      os.Getenv("MAXMIND_ACCOUNT_ID"),
		DNSServers:            getEnv("DNS_SERVERS", "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query"),
		BootstrapDNS:          getEnv("BOOTSTRAP_DNS", "1.1.1.1,9.9.9.9"),
		SEOEnabled:            getEnvBool("SEO_ENABLED", false),
		SEODomain:             getEnv("SEO_DOMAIN", ""),
		AllowedDomain:         getEnv("ALLOWED_DOMAIN", ""),
		SkipOriginCheck:       getEnvBool("WS_SKIP_ORIGIN_CHECK", false),
		AllowPrivateIPs:       getEnvBool("ALLOW_PRIVATE_IPS", false),
		AllowLoopbackIPs:      getEnvBool("ALLOW_LOOPBACK_IPS", false),
		AllowLinkLocalIPs:     getEnvBool("ALLOW_LINK_LOCAL_IPS", false),
		CORSOrigins:           getEnv("CORS_ORIGINS", ""),
		Environment:           getEnv("ENVIRONMENT", "development"),
		AllowDevCors:          getEnvBool("ALLOW_DEV_CORS", false),
		MaxTargetConcurrency:  getEnvInt("MAX_TARGET_CONCURRENCY", 4, 1, 64),
		MaxServiceConcurrency: getEnvInt("MAX_SERVICE_CONCURRENCY", 12, 1, 128),
		PortScanConcurrency:   getEnvInt("PORT_SCAN_CONCURRENCY", 32, 1, 256),
		PortScanMaxPorts:      getEnvInt("PORT_SCAN_MAX_PORTS", 1024, 1, 65535),
		DNSMaxAttempts:        getEnvInt("DNS_MAX_ATTEMPTS", 3, 1, 10),
	}

	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("SECRET_KEY environment variable is required")
	}
	if err := validateConfiguredValues(); err != nil {
		return nil, err
	}
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		return nil, fmt.Errorf("ENVIRONMENT must be development, test, or production")
	}
	if cfg.Environment == "production" {
		if cfg.ConfigUser == "" || strings.EqualFold(cfg.ConfigUser, "admin") || strings.EqualFold(cfg.ConfigUser, "change_me") {
			return nil, fmt.Errorf("CONFIG_USER must be changed for production")
		}
		if len(cfg.ConfigPass) < 12 || strings.EqualFold(cfg.ConfigPass, "change_me") || strings.EqualFold(cfg.ConfigPass, "admin") {
			return nil, fmt.Errorf("CONFIG_PASS must contain at least 12 characters and not be a known placeholder in production")
		}
		if len(cfg.SecretKey) < 32 || strings.Contains(strings.ToUpper(cfg.SecretKey), "DO_NOT_USE") {
			return nil, fmt.Errorf("SECRET_KEY must contain at least 32 characters and not be a known placeholder in production")
		}
	}
	if cfg.TrustProxy || cfg.UseCloudflare {
		if strings.TrimSpace(cfg.TrustedProxies) == "" {
			return nil, fmt.Errorf("TRUSTED_PROXIES is required when proxy client-IP headers are enabled")
		}
		for _, entry := range strings.Split(cfg.TrustedProxies, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if net.ParseIP(entry) == nil {
				if _, _, err := net.ParseCIDR(entry); err != nil {
					return nil, fmt.Errorf("TRUSTED_PROXIES contains invalid IP/CIDR %q", entry)
				}
			}
		}
	}

	return cfg, nil
}

func validateConfiguredValues() error {
	boolKeys := []string{
		"TRUST_PROXY", "USE_CLOUDFLARE", "ENABLE_GEO", "ENABLE_SSL", "ENABLE_WHOIS",
		"ENABLE_DNS", "ENABLE_CT", "ENABLE_HTTP", "AUTO_UPDATE_DATABASES", "SEO_ENABLED", "WS_SKIP_ORIGIN_CHECK",
		"ALLOW_PRIVATE_IPS", "ALLOW_LOOPBACK_IPS", "ALLOW_LINK_LOCAL_IPS", "ALLOW_DEV_CORS",
	}
	for _, key := range boolKeys {
		if value, ok := os.LookupEnv(key); ok {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "false", "1", "0":
			default:
				return fmt.Errorf("%s must be true, false, 1, or 0", key)
			}
		}
	}
	intSettings := []struct {
		key          string
		minimum, max int
	}{
		{"MAX_TARGET_CONCURRENCY", 1, 64}, {"MAX_SERVICE_CONCURRENCY", 1, 128},
		{"PORT_SCAN_CONCURRENCY", 1, 256}, {"PORT_SCAN_MAX_PORTS", 1, 65535},
		{"DNS_MAX_ATTEMPTS", 1, 10},
	}
	for _, setting := range intSettings {
		if value, ok := os.LookupEnv(setting.key); ok {
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || parsed < setting.minimum || parsed > setting.max {
				return fmt.Errorf("%s must be an integer from %d through %d", setting.key, setting.minimum, setting.max)
			}
		}
	}
	return nil
}

func getEnvInt(key string, fallback, minimum, maximum int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return fallback
}
