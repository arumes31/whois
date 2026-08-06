//go:build stress

package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStressPortScanner(t *testing.T) {
	target := "127.0.0.1"
	ports := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		ports[i] = i + 1
	}

	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	dialer := func(context.Context, string, []net.IPAddr, string, time.Duration) (net.Conn, string, error) {
		return nil, "", errors.New("connection refused")
	}
	options := DefaultScanOptions()
	options.Concurrency = 32
	options.MaxPorts = len(ports)

	var wg sync.WaitGroup
	var callbacks atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := scanPortsStreamWithOptions(
				context.Background(), target, ports, options,
				func(int, string, error) { callbacks.Add(1) }, resolver, dialer,
			)
			if got := len(result.Closed); got != len(ports) {
				t.Errorf("closed ports = %d; want %d", got, len(ports))
			}
		}()
	}
	wg.Wait()
	if got, want := callbacks.Load(), int64(10*len(ports)); got != want {
		t.Fatalf("callbacks = %d; want %d", got, want)
	}
}

func TestStressDNSLookup(t *testing.T) {
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}), "udp")
	s := NewDNSService(resolver, "")
	target := "example.test"

	var wg sync.WaitGroup
	var completed atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.LookupStream(ctx, target, false, func(string, interface{}) {}); err != nil {
				t.Errorf("lookup failed: %v", err)
				return
			}
			completed.Add(1)
		}()
	}
	wg.Wait()
	if got := completed.Load(); got != 50 {
		t.Fatalf("completed lookups = %d; want 50", got)
	}
}
