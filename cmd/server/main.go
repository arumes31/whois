package main

import (
	"context"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"time"
	"whois/internal/handler"
	"whois/internal/service"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// Config
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost"
	}
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	// Dependencies
	store := storage.NewStorage(redisHost, redisPort)
	h := handler.NewHandler(store)
	sched := service.NewScheduler(store)

	// Startup tasks
	go service.DownloadBackground()
	sched.Start()

	// Web Server
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20))) // 20 requests per second

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
		if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
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
