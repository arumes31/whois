package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
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

const contentSecurityPolicyBase = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'"

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

	e, closeServer := NewServer(cfg)

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
		utils.Log.Error("HTTP shutdown did not complete cleanly", utils.Field("error", err.Error()))
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	if err := closeServer(cleanupCtx); err != nil {
		utils.Log.Error("application cleanup did not complete cleanly", utils.Field("error", err.Error()))
	}
}

func NewServer(cfg *config.Config) (*echo.Echo, func(context.Context) error) {
	// Dependencies
	store := storage.NewStorage(cfg.RedisHost, cfg.RedisPort)
	store.ConfigureDNSHistory(
		cfg.DNSHistoryMaxTargets,
		time.Duration(cfg.DNSHistoryTTLHours)*time.Hour,
	)
	h := handler.NewHandler(store, cfg)
	sched := service.NewScheduler(store, cfg.DNSServers, cfg.BootstrapDNS)
	appCtx, appCancel := context.WithCancel(context.Background())
	var initializerWG sync.WaitGroup

	// Load local lookup data without generating startup traffic. Operators can
	// explicitly opt into remote database downloads and periodic updates.
	if cfg.EnableGeo {
		service.ReloadGeoDB()
	}
	if cfg.AutoUpdateDatabases {
		if cfg.EnableGeo {
			initializerWG.Add(1)
			go func() {
				defer initializerWG.Done()
				service.InitializeGeoDBContext(appCtx, cfg.MaxMindLicenseKey, cfg.MaxMindAccountID)
			}()
		}
		initializerWG.Add(1)
		go func() {
			defer initializerWG.Done()
			service.InitializeMACServiceContext(appCtx)
		}()
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
	e.Server.ReadTimeout = 15 * time.Second
	e.Server.IdleTimeout = 60 * time.Second
	e.Server.MaxHeaderBytes = 64 << 10
	e.Server.RegisterOnShutdown(func() {
		appCancel()
		h.Close()
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
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper: wsSkipper,
		Level:   5,
	}))
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		Skipper: wsSkipper,
		// Multipart boundaries and part headers sit outside the uploaded file.
		// BulkUpload independently keeps the actual file at 2 MiB.
		Limit: "3M",
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
		ContentSecurityPolicy: contentSecurityPolicyBase + ";",
	}))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			policy := contentSecurityPolicyBase
			if source, ok := handler.WebSocketConnectSource(c.Request(), cfg); ok {
				policy += " " + source
			}
			c.Response().Header().Set(echo.HeaderContentSecurityPolicy, policy+";")
			c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			c.Response().Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			if strings.HasPrefix(c.Request().URL.Path, "/static/") {
				c.Response().Header().Set(echo.HeaderCacheControl, "public, max-age=3600, must-revalidate")
			}
			return next(c)
		}
	})

	// CSRF Protection
	csrfSkipper := func(c echo.Context) bool {
		if wsSkipper(c) || strings.HasPrefix(c.Request().URL.Path, "/static/") {
			return true
		}
		switch c.Request().URL.Path {
		case "/livez", "/readyz", "/health", "/metrics", "/system-stats", "/robots.txt":
			return true
		default:
			return false
		}
	}
	// #nosec G101 -- TokenLookup and CookieName are CSRF field names, not credentials.
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper:        csrfSkipper,
		TokenLookup:    "form:_csrf,header:X-CSRF-Token",
		CookieName:     "_csrf",
		CookieHTTPOnly: true,
		CookieSecure:   cfg.SessionCookieSecure,
		CookieSameSite: http.SameSiteLaxMode,
	}))

	// Templates
	e.Renderer = &utils.TemplateRegistry{
		Templates: template.Must(template.New("").Funcs(template.FuncMap{
			"IsIP": utils.IsIP,
		}).ParseGlob("templates/*.html")),
	}

	// Static assets use an explicit HEAD route and do not allocate CSRF cookies.
	staticFiles := http.StripPrefix("/static/", http.FileServer(http.Dir("static")))
	e.GET("/static/*", echo.WrapHandler(staticFiles))
	e.HEAD("/static/*", echo.WrapHandler(staticFiles))

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
	readOnlyDataLimiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      2,
			Burst:     10,
			ExpiresIn: 5 * time.Minute,
		}),
	})
	// DNS answers are public data and the dashboard requires unauthenticated
	// history reads. Normalization in GetHistory plus this per-IP limiter bounds
	// the public surface without making the dashboard depend on config auth.
	e.GET("/history", h.GetHistory, readOnlyDataLimiter)
	e.GET("/history/:item", h.GetHistory, readOnlyDataLimiter)
	e.GET("/system-stats", h.SystemStats, readOnlyDataLimiter)

	// Protected routes use route-local middleware so unrelated 404s remain 404s.
	e.GET("/config", h.Config, h.LoginRequired)
	e.POST("/config", h.Config, h.LoginRequired)
	e.POST("/config/update-geo", h.UpdateGeoDB, h.LoginRequired)
	e.POST("/logout", h.Logout, h.LoginRequired)

	var closeOnce sync.Once
	closeDone := make(chan struct{})
	var closeErr error
	closeServer := func(ctx context.Context) error {
		closeOnce.Do(func() {
			appCancel()
			h.Close()

			if err := h.WaitForClose(ctx); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("wait for websocket handlers: %w", err))
			}

			initializersDone := make(chan struct{})
			go func() {
				initializerWG.Wait()
				close(initializersDone)
			}()
			select {
			case <-initializersDone:
			case <-ctx.Done():
				closeErr = errors.Join(closeErr, fmt.Errorf("wait for database initializers: %w", ctx.Err()))
			}

			service.StopGeoDBUpdater()
			service.StopMACService()
			service.CloseGeoDB()

			cronDone := sched.Cron.Stop()
			select {
			case <-cronDone.Done():
			case <-ctx.Done():
				closeErr = errors.Join(closeErr, fmt.Errorf("wait for scheduler: %w", ctx.Err()))
			}

			if closer, ok := store.Client.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					closeErr = errors.Join(closeErr, fmt.Errorf("close storage: %w", err))
				}
			}
			close(closeDone)
		})

		select {
		case <-closeDone:
			return closeErr
		case <-ctx.Done():
			return errors.Join(closeErr, ctx.Err())
		}
	}

	return e, closeServer
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
