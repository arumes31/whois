package main

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"whois/internal/config"
	"whois/internal/handler"
	"whois/internal/service"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Load .env file if it exists
	_ = godotenv.Load()

	utils.InitLogger()
	defer func() {
		_ = utils.Log.Sync()
	}()

	cfg, err := config.LoadConfig()
	if err != nil {
		utils.Log.Fatal("config load failed", utils.Field("error", err.Error()))
	}

	utils.SetAllowPrivateIPs(cfg.AllowPrivateIPs)
	utils.SetAllowLoopbackIPs(cfg.AllowLoopbackIPs)
	utils.SetAllowLinkLocalIPs(cfg.AllowLinkLocalIPs)

	e := NewServer(cfg)

	// Start server
	go func() {
		utils.Log.Info("starting server", utils.Field("port", cfg.Port))
		if err := e.Start(":" + cfg.Port); err != nil && err != http.ErrServerClosed {
			utils.Log.Fatal("shutting down the server")
		}
	}()

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

func NewServer(cfg *config.Config) *echo.Echo {
	// Dependencies
	store := storage.NewStorage(cfg.RedisHost, cfg.RedisPort)
	h := handler.NewHandler(store, cfg)
	sched := service.NewScheduler(store, cfg.DNSServers, cfg.BootstrapDNS)

	// Load local lookup data without generating startup traffic. Operators can
	// explicitly opt into remote database downloads and periodic updates.
	if cfg.EnableGeo {
		service.ReloadGeoDB()
	}
	if cfg.AutoUpdateDatabases {
		if cfg.EnableGeo {
			go service.InitializeGeoDB(cfg.MaxMindLicenseKey, cfg.MaxMindAccountID)
		}
		go service.InitializeMACService()
	}
	sched.Start()

	// Web Server
	e := echo.New()
	e.HideBanner = true
	e.IPExtractor = echo.ExtractIPDirect()
	trustedNetworks := parseTrustedNetworks(cfg.TrustedProxies)
	if cfg.TrustProxy {
		trustOptions := []echo.TrustOption{
			echo.TrustLoopback(false),
			echo.TrustLinkLocal(false),
			echo.TrustPrivateNet(false),
		}
		for _, network := range trustedNetworks {
			trustOptions = append(trustOptions, echo.TrustIPRange(network))
		}
		e.IPExtractor = echo.ExtractIPFromXFFHeader(trustOptions...)
	}
	if cfg.UseCloudflare {
		baseExtractor := e.IPExtractor
		e.IPExtractor = func(request *http.Request) string {
			directIP := echo.ExtractIPDirect()(request)
			if ipInNetworks(directIP, trustedNetworks) {
				if cloudflareIP := net.ParseIP(strings.TrimSpace(request.Header.Get("CF-Connecting-IP"))); cloudflareIP != nil {
					return cloudflareIP.String()
				}
			}
			return baseExtractor(request)
		}
	}
	e.Server.ReadHeaderTimeout = 5 * time.Second
	e.Server.IdleTimeout = 60 * time.Second
	e.Server.MaxHeaderBytes = 1 << 20
	e.Server.RegisterOnShutdown(func() {
		h.Close()
		service.StopGeoDBUpdater()
		service.StopMACService()
		sched.Cron.Stop()
		if closer, ok := store.Client.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})

	// Prometheus endpoint with IP restriction
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()), h.Metrics)

	// Security Middlewares
	wsSkipper := func(c echo.Context) bool {
		return c.Path() == "/ws"
	}

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true,
		LogURI:    true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			utils.Log.Info("request",
				utils.Field("uri", v.URI),
				utils.Field("status", v.Status),
			)
			return nil
		},
	}))
	e.Use(middleware.Recover())
	var allowOrigins []string
	if cfg.CORSOrigins != "" {
		for _, org := range strings.Split(cfg.CORSOrigins, ",") {
			trimmed := strings.TrimSpace(org)
			if trimmed != "" {
				allowOrigins = append(allowOrigins, trimmed)
			}
		}
	}
	if len(allowOrigins) == 0 {
		if cfg.Environment == "development" || cfg.AllowDevCors {
			allowOrigins = []string{"*"}
		} else {
			allowOrigins = []string{"none"}
		}
	}
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper:      wsSkipper,
		AllowOrigins: allowOrigins,
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		Skipper: wsSkipper,
		Limit:   "2M",
	}))
	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStore(20),
	}))

	// Secure Headers
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		Skipper:               wsSkipper,
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:;",
	}))

	// CSRF Protection
	// #nosec G101
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper:        wsSkipper,
		TokenLookup:    "form:_csrf,header:X-CSRF-Token",
		CookieName:     "_csrf",
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteLaxMode,
	}))

	// Templates
	e.Renderer = &utils.TemplateRegistry{
		Templates: template.Must(template.New("").Funcs(template.FuncMap{
			"IsIP": utils.IsIP,
		}).ParseGlob("templates/*.html")),
	}

	// Static
	e.Static("/static", "static")

	// Custom HTTP Error Handler
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}

		errorData := map[string]interface{}{
			"Code":    code,
			"Message": http.StatusText(code),
			"real_ip": utils.ExtractIP(c, utils.ProxyConfig{TrustProxy: cfg.TrustProxy, UseCloudflare: cfg.UseCloudflare}),
		}

		if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
			c.Logger().Error(renderErr)
		}
	}

	// Routes
	e.GET("/livez", h.Liveness)
	e.GET("/readyz", h.Health)
	e.GET("/health", h.Health) // Backward-compatible readiness alias.
	e.GET("/robots.txt", h.Robots)
	e.GET("/", h.Index)
	e.POST("/", h.Index)
	e.POST("/dns_lookup", h.DNSLookup)
	e.POST("/mac_lookup", h.MacLookup)
	e.POST("/bulk-upload", h.BulkUpload)
	e.GET("/ws", h.HandleWS)
	e.GET("/login", h.Login)
	e.POST("/login", h.Login)
	e.GET("/scanner", h.Scanner)
	e.POST("/scan", h.Scan)
	e.GET("/history/:item", h.GetHistory)

	// Protected
	g := e.Group("")
	g.Use(h.LoginRequired)
	g.GET("/config", h.Config)
	g.POST("/config", h.Config)
	g.POST("/config/update-geo", h.UpdateGeoDB)
	g.GET("/logout", h.Logout)

	return e
}

func parseTrustedNetworks(entries string) []*net.IPNet {
	networks := make([]*net.IPNet, 0)
	for _, entry := range strings.Split(entries, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			networks = append(networks, network)
		} else {
			utils.Log.Warn("ignoring invalid trusted proxy range", utils.Field("range", entry))
		}
	}
	return networks
}

func ipInNetworks(rawIP string, networks []*net.IPNet) bool {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
