package main

import (
	"context"
	"html/template"
	"net/http"
	"os"
	"os/signal"
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
	signal.Notify(quit, os.Interrupt)
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

	// Startup tasks
	go service.DownloadBackground()
	service.InitializeGeoDB(cfg.MaxMindLicenseKey, cfg.MaxMindAccountID)
	service.InitializeMACService()
	sched.Start()

	// Web Server
	e := echo.New()
	e.HideBanner = true

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
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper:      wsSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		Skipper: wsSkipper,
		Limit:   "1M",
	}))
	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: wsSkipper,
		Store:   middleware.NewRateLimiterMemoryStore(20),
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
	e.GET("/health", h.Health)
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
