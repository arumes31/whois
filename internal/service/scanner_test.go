package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanPorts(t *testing.T) {
	// Scan localhost (assuming common ports might be closed/open)
	// We'll scan a known open port if possible, but 127.0.0.1 is safe.
	ports := []int{80, 443}
	res := ScanPorts(context.Background(), "127.0.0.1", ports)

	if res.Elapsed < 0 {
		t.Errorf("Elapsed time should be non-negative")
	}

	total := len(res.Open) + len(res.Closed)
	if total != len(ports) {
		t.Errorf("Expected %d total results, got %d", len(ports), total)
	}
}

func TestScanPorts_Open(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	host := "127.0.0.1"

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("test banner"))
			_ = conn.Close()
		}
	}()

	res := ScanPorts(context.Background(), host, []int{port})
	if _, ok := res.Open[port]; !ok {
		t.Errorf("Expected port %d to be open", port)
	}
	if !strings.Contains(res.Open[port], "test banner") {
		t.Errorf("Expected banner 'test banner', got '%s'", res.Open[port])
	}
}

func TestScanPortsStream_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ports := []int{80, 443}
	res := ScanPortsStream(ctx, "127.0.0.1", ports, nil)

	// Should return early with empty results
	if len(res.Open) > 0 || len(res.Closed) > 0 {
		t.Error("Expected 0 results for cancelled context")
	}
}

func TestScanPortsStream_LateCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// We want to trigger the second ctx.Done() check inside the loop
	// This is hard without a large number of ports or sleeps,
	// but we can try to fill the semaphore or just call it after starting some.

	ports := make([]int, 100)
	for i := range ports {
		ports[i] = 1000 + i
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_ = ScanPortsStream(ctx, "127.0.0.1", ports, nil)
}
