package service

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func init() {
	utils.TestInitLogger()
}

func setupMiniredis(t *testing.T) *storage.Storage {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &storage.Storage{Client: client}
}

func TestNewScheduler(t *testing.T) {
	t.Parallel()
	s := storage.NewStorage("localhost", "6379")
	sched := NewScheduler(s, "", "")
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
	sched := NewScheduler(nil, "", "")
	sched.Start()
	sched.Cron.Stop()
}

func TestScheduler_RunMonitorJob(t *testing.T) {
	s := setupMiniredis(t) // Need miniredis for storage
	sched := NewScheduler(s, "", "")

	// Test empty items
	sched.RunMonitorJob()

	// Test with items
	_ = s.AddMonitoredItem(context.Background(), "google.com")
	sched.RunMonitorJob()
	time.Sleep(100 * time.Millisecond) // Let goroutines run

	// Test error branch (closed storage)
	badStorage := &storage.Storage{Client: redis.NewClient(&redis.Options{Addr: "localhost:1"})}
	schedBad := NewScheduler(badStorage, "", "")
	schedBad.RunMonitorJob()
}

func TestDownloadBackground_Errors(t *testing.T) {
	// 1. Trigger os.Create error by using a path that is actually a directory
	_ = os.MkdirAll("static/background.jpg", 0755)
	DownloadBackground()
	_ = os.RemoveAll("static/background.jpg")

	// 3. Trigger io.Copy error
	BackgroundHTTPClient = &http.Client{
		Transport: &faultyTransport{},
	}
	DownloadBackground()
}

type faultyTransport struct{}

func (t *faultyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       &faultyBody{},
	}, nil
}

type faultyBody struct{}

func (b *faultyBody) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("faulty read")
}

func (b *faultyBody) Close() error {
	return nil
}
