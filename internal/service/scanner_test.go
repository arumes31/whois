package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"whois/internal/utils"
)

func TestScanPorts(t *testing.T) {
	allowPrivate := utils.GetAllowPrivateIPs()
	utils.SetAllowPrivateIPs(true)
	t.Cleanup(func() { utils.SetAllowPrivateIPs(allowPrivate) })

	// Scan localhost (assuming common ports might be closed/open)
	// We'll scan a known open port if possible, but 127.0.0.1 is safe.
	ports := []int{80, 443}
	res := ScanPorts(context.Background(), "127.0.0.1", ports)

	if res.Elapsed < 0 {
		t.Errorf("Elapsed time should be non-negative")
	}

	total := len(res.Open) + len(res.Closed) + len(res.Filtered)
	if total != len(ports) {
		t.Errorf("Expected %d total results, got %d", len(ports), total)
	}
}

func TestScanPorts_Open(t *testing.T) {
	allowPrivate := utils.GetAllowPrivateIPs()
	utils.SetAllowPrivateIPs(true)
	t.Cleanup(func() { utils.SetAllowPrivateIPs(allowPrivate) })

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
	if len(res.Error) != 1 || !strings.Contains(res.Error[0], context.Canceled.Error()) {
		t.Fatalf("expected cancellation error, got %v", res.Error)
	}
}

func TestScanPortsStream_LateCancel(t *testing.T) {
	allowPrivate := utils.GetAllowPrivateIPs()
	utils.SetAllowPrivateIPs(true)
	t.Cleanup(func() { utils.SetAllowPrivateIPs(allowPrivate) })

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

func TestScanPortsResolvesOnceAndClassifiesFailures(t *testing.T) {
	resolveCalls := 0
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		resolveCalls++
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	var dialMu sync.Mutex
	dialed := make([]int, 0, 2)
	dialer := func(_ context.Context, _ string, addresses []net.IPAddr, port string, _ time.Duration) (net.Conn, string, error) {
		if len(addresses) != 1 || !addresses[0].IP.Equal(net.ParseIP("203.0.113.10")) {
			t.Fatalf("dial received an unexpected address snapshot: %#v", addresses)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil {
			t.Fatalf("invalid port passed to dialer: %q", port)
		}
		dialMu.Lock()
		dialed = append(dialed, portNumber)
		dialMu.Unlock()
		if portNumber == 80 {
			return nil, "", fmt.Errorf("dial: %w", syscall.ECONNREFUSED)
		}
		return nil, "", fmt.Errorf("dial: %w", context.DeadlineExceeded)
	}

	result := scanPortsStreamWithOptions(context.Background(), "scan.example", []int{81, 80, 81, 0}, ScanOptions{
		Concurrency:    2,
		MaxPorts:       10,
		ConnectTimeout: time.Second,
		BannerTimeout:  time.Second,
	}, nil, resolver, dialer)

	if resolveCalls != 1 {
		t.Fatalf("resolved %d times; want exactly once", resolveCalls)
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed %v; want each unique valid port once", dialed)
	}
	if len(result.Closed) != 1 || result.Closed[0] != 80 {
		t.Fatalf("closed ports = %v; want [80]", result.Closed)
	}
	if len(result.Filtered) != 1 || result.Filtered[0] != 81 {
		t.Fatalf("filtered ports = %v; want [81]", result.Filtered)
	}
	if len(result.Error) != 1 || !strings.Contains(result.Error[0], "outside 1-65535") {
		t.Fatalf("errors = %v; want invalid-port detail", result.Error)
	}
}

func TestScanPortsCancellationInterruptsBannerRead(t *testing.T) {
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	connected := make(chan struct{})
	peerDone := make(chan struct{})
	dialer := func(context.Context, string, []net.IPAddr, string, time.Duration) (net.Conn, string, error) {
		client, peer := net.Pipe()
		close(connected)
		go func() {
			defer close(peerDone)
			defer func() { _ = peer.Close() }()
			buffer := make([]byte, 1)
			_, _ = peer.Read(buffer)
		}()
		return client, "203.0.113.10", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan ScanResult, 1)
	go func() {
		finished <- scanPortsStreamWithOptions(ctx, "scan.example", []int{443}, ScanOptions{
			Concurrency:    1,
			MaxPorts:       1,
			ConnectTimeout: time.Second,
			BannerTimeout:  time.Hour,
		}, nil, resolver, dialer)
	}()
	<-connected
	cancel()

	select {
	case result := <-finished:
		if len(result.Open) != 0 || len(result.Closed) != 0 || len(result.Filtered) != 0 {
			t.Fatalf("canceled scan reported port results: %#v", result)
		}
		if len(result.Error) != 1 || !strings.Contains(result.Error[0], context.Canceled.Error()) {
			t.Fatalf("expected cancellation error, got %v", result.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled scan did not interrupt the banner read")
	}
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("scanner did not close the connection after cancellation")
	}
}

func TestIsConnectionRefused(t *testing.T) {
	t.Parallel()
	if !isConnectionRefused(fmt.Errorf("wrapped: %w", syscall.ECONNREFUSED)) {
		t.Fatal("wrapped connection refusal was not recognized")
	}
	if isConnectionRefused(errors.New("network unreachable")) {
		t.Fatal("unreachable error was classified as a refusal")
	}
}

func TestParsePortSpec(t *testing.T) {
	t.Parallel()
	ports, err := ParsePortSpec("web,22,8000-8002,22", 32)
	if err != nil {
		t.Fatalf("ParsePortSpec failed: %v", err)
	}
	wanted := []int{22, 80, 443, 8000, 8001, 8002, 8080, 8443, 8888}
	if len(ports) != len(wanted) {
		t.Fatalf("got %v; want %v", ports, wanted)
	}
	for i := range wanted {
		if ports[i] != wanted[i] {
			t.Fatalf("got %v; want %v", ports, wanted)
		}
	}
}

func TestParsePortSpecRejectsUnsafeSelections(t *testing.T) {
	t.Parallel()
	for _, spec := range []string{"0", "65536", "1-100"} {
		if _, err := ParsePortSpec(spec, 10); err == nil {
			t.Errorf("ParsePortSpec(%q) unexpectedly succeeded", spec)
		}
	}
}
