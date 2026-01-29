package service

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	Cron    *cron.Cron
	Storage *storage.Storage
	Monitor *MonitorService
}

func NewScheduler(s *storage.Storage, resolvers string, bootstrap string) *Scheduler {
	c := cron.New()
	return &Scheduler{
		Cron:    c,
		Storage: s,
		Monitor: NewMonitorService(s, resolvers, bootstrap),
	}
}

func (s *Scheduler) Start() {
	// Background image update every 6 hours
	_, _ = s.Cron.AddFunc("@every 6h", func() {
		DownloadBackground()
	})

	// Monitoring refresh every 5 minutes (to reschedule if items changed)
	// Simplified: just run all monitored items once a day or spread them.
	// For now, let's just add a job that runs through monitored items.
	_, _ = s.Cron.AddFunc("0 2 * * *", func() { // Every day at 2 AM
		items, err := s.Storage.GetMonitoredItems(context.Background())
		if err != nil {
			utils.Log.Error("scheduler error getting items", utils.Field("error", err.Error()))
			return
		}
		for _, item := range items {
			go s.Monitor.RunCheck(context.Background(), item)
		}
	})

	s.Cron.Start()
	utils.Log.Info("scheduler started")
}

func DownloadBackground() {
	utils.Log.Info("downloading background image...")
	resp, err := http.Get("https://picsum.photos/1920/1080?grayscale")
	if err != nil {
		utils.Log.Error("failed to download background", utils.Field("error", err.Error()))
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	outPath := filepath.Join("static", "background.jpg")
	out, err := os.Create(outPath)
	if err != nil {
		utils.Log.Error("failed to create background file", utils.Field("error", err.Error()))
		return
	}
	defer func() {
		_ = out.Close()
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		utils.Log.Error("failed to save background", utils.Field("error", err.Error()))
	} else {
		utils.Log.Info("background image updated")
	}
}
