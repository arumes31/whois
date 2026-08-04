package service

import (
	"context"
	"errors"
	"sync"
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

func TestScheduler_Start(t *testing.T) {
	sched := NewScheduler(nil, "", "")
	sched.Start()
	sched.Cron.Stop()
}

func TestScheduler_RunMonitorJob(t *testing.T) {
	s := setupMiniredis(t) // Need miniredis for storage
	sched := NewScheduler(s, "", "")
	dns := &monitorDNSStub{result: map[string]interface{}{"A": []string{"192.0.2.1"}}}
	sched.Monitor.DNS = dns
	sched.JobTimeout = time.Second
	sched.MaxConcurrency = 2

	// Test empty items
	sched.RunMonitorJob()

	// Test with items
	_ = s.AddMonitoredItem(context.Background(), "example.com")
	_ = s.AddMonitoredItem(context.Background(), "example.com")
	sched.RunMonitorJob() // blocks until all goroutines complete (wg.Wait inside)
	if dns.Calls() != 1 {
		t.Fatalf("expected duplicate monitored targets to run once, got %d calls", dns.Calls())
	}
	history, err := s.GetDNSHistory(context.Background(), "example.com")
	if err != nil || len(history) != 1 {
		t.Fatalf("expected one stored DNS result, got %d entries and error %v", len(history), err)
	}

	// Test error branch (closed storage)
	badStorage := &storage.Storage{Client: redis.NewClient(&redis.Options{
		Addr:        "localhost:1",
		DialTimeout: 10 * time.Millisecond,
		ReadTimeout: 10 * time.Millisecond,
	})}
	schedBad := NewScheduler(badStorage, "", "")
	schedBad.JobTimeout = 50 * time.Millisecond
	schedBad.RunMonitorJob()
}

type monitorDNSStub struct {
	mu     sync.Mutex
	result map[string]interface{}
	err    error
	calls  int
}

func (s *monitorDNSStub) Lookup(context.Context, string, bool) (map[string]interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func (s *monitorDNSStub) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestMonitorService_RunCheckFailureDoesNotStoreHistory(t *testing.T) {
	store := setupMiniredis(t)
	monitor := NewMonitorService(store, "", "")
	monitor.DNS = &monitorDNSStub{err: errors.New("resolver unavailable")}

	monitor.RunCheck(context.Background(), "example.com")
	history, err := store.GetDNSHistory(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Fatalf("failed DNS checks must not be stored as successful history: %#v", history)
	}
}
