package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	RedisHost         string
	RedisPort         string
	Port              string
	ConfigUser        string
	ConfigPass        string
	SecretKey         string
	TrustedIPs        string
	TrustProxy        bool
	UseCloudflare     bool
	EnableGeo         bool
	EnableSSL         bool
	EnableWhois       bool
	EnableDNS         bool
	EnableCT          bool
	EnableHTTP        bool
	MaxMindLicenseKey string
	MaxMindAccountID  string
	DNSResolver       string
	DNSServers        string
	BootstrapDNS      string
	SEOEnabled        bool
	SEODomain         string
	AllowedDomain     string
	SkipOriginCheck   bool
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		RedisHost:  getEnv("REDIS_HOST", "localhost"),
		RedisPort:  getEnv("REDIS_PORT", "6379"),
		Port:       getEnv("PORT", "5000"),
		ConfigUser: getEnv("CONFIG_USER", "admin"),
		ConfigPass: getEnv("CONFIG_PASS", "admin"), SecretKey: os.Getenv("SECRET_KEY"),
		TrustedIPs:        getEnv("TRUSTED_IPS", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"),
		TrustProxy:        getEnvBool("TRUST_PROXY", true),
		UseCloudflare:     getEnvBool("USE_CLOUDFLARE", false),
		EnableGeo:         getEnvBool("ENABLE_GEO", true),
		EnableSSL:         getEnvBool("ENABLE_SSL", true),
		EnableWhois:       getEnvBool("ENABLE_WHOIS", true),
		EnableDNS:         getEnvBool("ENABLE_DNS", true),
		EnableCT:          getEnvBool("ENABLE_CT", true),
		EnableHTTP:        getEnvBool("ENABLE_HTTP", true),
		MaxMindLicenseKey: os.Getenv("MAXMIND_LICENSE_KEY"),
		MaxMindAccountID:  os.Getenv("MAXMIND_ACCOUNT_ID"),
		DNSResolver:       getEnv("DNS_RESOLVER", "8.8.8.8:53"),
		DNSServers:        getEnv("DNS_SERVERS", "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query"),
		BootstrapDNS:      getEnv("BOOTSTRAP_DNS", "1.1.1.1,9.9.9.9"),
		SEOEnabled:        getEnvBool("SEO_ENABLED", false),
		SEODomain:         getEnv("SEO_DOMAIN", ""),
		AllowedDomain:     getEnv("ALLOWED_DOMAIN", ""),
		SkipOriginCheck:   getEnvBool("WS_SKIP_ORIGIN_CHECK", false),
	}

	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("SECRET_KEY environment variable is required")
	}

	return cfg, nil
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
