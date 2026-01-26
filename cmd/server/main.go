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

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	utils.InitLogger()
	defer utils.Log.Sync()

	cfg, err := config.LoadConfig()
	if err != nil {
		utils.Log.Fatal("config load failed", utils.Field("error", err.Error()))
	}

	// Dependencies
	store := storage.NewStorage(cfg.RedisHost, cfg.RedisPort)
	h := handler.NewHandler(store, cfg)
	sched := service.NewScheduler(store)

	// Startup tasks
	go service.DownloadBackground()
	sched.Start()

	// Web Server
	e := echo.New()
	e.HideBanner = true
	
	// Prometheus endpoint with IP restriction
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()), func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if utils.IsTrustedIP(c.RealIP(), cfg.TrustedIPs) {
				return next(c)
			}
			return c.NoContent(http.StatusForbidden)
		}
	})
	
	// Security Middlewares
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit("1M")) // Prevent large payload attacks
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))
	
	// Secure Headers
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;",
	}))

	// CSRF Protection
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:_csrf,header:X-CSRF-Token",
		CookieName:  "_csrf",
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
		}
		
		if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
			c.Logger().Error(renderErr)
		}
	}

	// Routes
	e.GET("/", h.Index)
	e.POST("/", h.Index)
	e.POST("/scan", h.Scan) // HTMX
	e.POST("/dns_lookup", h.DNSLookup)
	e.POST("/mac_lookup", h.MacLookup)
	e.GET("/ws", h.HandleWS)
	e.GET("/login", h.Login)
	e.POST("/login", h.Login)
	
	// Protected
	g := e.Group("")
	g.Use(h.LoginRequired)
	g.GET("/config", h.Config)
	g.POST("/config", h.Config)
	g.GET("/logout", func(c echo.Context) error {
		c.SetCookie(&http.Cookie{Name: "session_id", MaxAge: -1})
		return c.Redirect(http.StatusFound, "/")
	})
	g.GET("/history/:item", func(c echo.Context) error {
		item := c.Param("item")
		entries, diffs, err := store.GetHistoryWithDiffs(c.Request().Context(), item)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"entries": entries,
			"diffs":   diffs,
		})
	})

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
