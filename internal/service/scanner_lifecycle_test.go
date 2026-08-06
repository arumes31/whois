package service

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestScannerWorkerLifecycle verifies the scanner's worker pool and the peer
// goroutines backing every in-flight connection have all exited when a caller
// cancels and ScanPorts returns. This is deterministic leak coverage: every
// observed goroutine has an explicit completion signal instead of relying on a
// timing-sensitive process-wide goroutine count.
func TestScannerWorkerLifecycle(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}

	const concurrency = 4
	connected := make(chan struct{}, concurrency)
	var peerMu sync.Mutex
	peerDone := make([]<-chan struct{}, 0, concurrency)
	dialer := func(context.Context, string, []net.IPAddr, string, time.Duration) (net.Conn, string, error) {
		client, peer := net.Pipe()
		done := make(chan struct{})
		peerMu.Lock()
		peerDone = append(peerDone, done)
		peerMu.Unlock()
		go func() {
			defer close(done)
			defer func() { _ = peer.Close() }()
			buffer := make([]byte, 1)
			_, _ = peer.Read(buffer)
		}()
		connected <- struct{}{}
		return client, "203.0.113.10", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan ScanResult, 1)
	go func() {
		finished <- scanPortsStreamWithOptions(ctx, "scan.example", []int{80, 81, 82, 83, 84, 85}, ScanOptions{
			Concurrency:    concurrency,
			MaxPorts:       6,
			ConnectTimeout: time.Second,
			BannerTimeout:  time.Hour,
		}, nil, resolver, dialer)
	}()

	for range concurrency {
		select {
		case <-connected:
		case <-time.After(time.Second):
			t.Fatal("scanner workers did not start")
		}
	}
	cancel()

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("scanner did not return after cancellation")
	}

	peerMu.Lock()
	peers := append([]<-chan struct{}(nil), peerDone...)
	peerMu.Unlock()
	for index, done := range peers {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("connection peer goroutine %d did not exit", index)
		}
	}
}
