package service

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"whois/internal/storage"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	Cron    *cron.Cron
	Storage *storage.Storage
	Monitor *MonitorService
}

func NewScheduler(s *storage.Storage) *Scheduler {
	c := cron.New()
	return &Scheduler{
		Cron:    c,
		Storage: s,
		Monitor: NewMonitorService(s),
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
			log.Printf("Scheduler error getting items: %v", err)
			return
		}
		for _, item := range items {
			go s.Monitor.RunCheck(context.Background(), item)
		}
	})

	s.Cron.Start()
	log.Println("Scheduler started")
}

func DownloadBackground() {
	log.Println("Downloading background image...")
	resp, err := http.Get("https://picsum.photos/1920/1080?grayscale")
	if err != nil {
		log.Printf("Failed to download background: %v", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	outPath := filepath.Join("static", "background.jpg")
	out, err := os.Create(outPath)
	if err != nil {
		log.Printf("Failed to create background file: %v", err)
		return
	}
	defer func() {
		_ = out.Close()
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Printf("Failed to save background: %v", err)
	} else {
		log.Println("Background image updated")
	}
}
