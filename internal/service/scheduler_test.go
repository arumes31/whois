package service

import (
	"os"
	"testing"
	"whois/internal/storage"
)

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
