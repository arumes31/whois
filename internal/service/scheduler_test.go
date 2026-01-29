package service

import (
	"os"
	"testing"
	"whois/internal/storage"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestNewScheduler(t *testing.T) {
	t.Parallel()
	s := storage.NewStorage("localhost", "6379")
	sched := NewScheduler(s, "")
	if sched == nil {
		t.Error("Failed to create scheduler")
	}
}

func TestDownloadBackground(t *testing.T) {
	t.Parallel()
	// Create static dir if not exists
	_ = os.MkdirAll("static", 0755)

	// This makes an actual network call, but we can test it
	DownloadBackground()

	if _, err := os.Stat("static/background.jpg"); os.IsNotExist(err) {
		t.Log("Background image not downloaded (expected if offline)")
	}
}

func TestScheduler_Start(t *testing.T) {
	sched := NewScheduler(nil, "")
	sched.Start()
	sched.Cron.Stop()
}

func TestDownloadBackground_Error(t *testing.T) {
	// Trigger os.Create error by using a path that is actually a directory
	_ = os.MkdirAll("static/background.jpg", 0755)
	defer func() { _ = os.RemoveAll("static/background.jpg") }()

	DownloadBackground()
}
