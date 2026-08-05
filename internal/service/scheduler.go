package service

import (
	"context"
	"sync"
	"time"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	Cron           *cron.Cron
	Storage        *storage.Storage
	Monitor        *MonitorService
	JobTimeout     time.Duration
	MaxConcurrency int
}

func NewScheduler(s *storage.Storage, resolvers string, bootstrap string) *Scheduler {
	c := cron.New()
	return &Scheduler{
		Cron:           c,
		Storage:        s,
		Monitor:        NewMonitorService(s, resolvers, bootstrap),
		JobTimeout:     10 * time.Minute,
		MaxConcurrency: 4,
	}
}

func (s *Scheduler) Start() {
	// Monitoring refresh every day at 2 AM
	_, _ = s.Cron.AddFunc("0 2 * * *", s.RunMonitorJob)

	s.Cron.Start()
	utils.Log.Info("scheduler started")
}

func (s *Scheduler) RunMonitorJob() {
	timeout := s.JobTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	items, err := s.Storage.GetMonitoredItems(ctx)
	if err != nil {
		utils.Log.Error("scheduler error getting items", utils.Field("error", err.Error()))
		return
	}

	limit := s.MaxConcurrency
	if limit < 1 {
		limit = 4
	}
	semaphore := make(chan struct{}, limit)
	seen := make(map[string]struct{}, len(items))
	var wg sync.WaitGroup

loop:
	for _, item := range items {
		if _, duplicate := seen[item]; duplicate {
			continue
		}
		seen[item] = struct{}{}

		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			break loop
		}

		wg.Add(1)
		go func(item string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			s.Monitor.RunCheck(ctx, item)
		}(item)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		utils.Log.Warn("monitoring job ended before all targets completed", utils.Field("error", err.Error()))
	}
}
