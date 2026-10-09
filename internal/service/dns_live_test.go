//go:build integration

package service

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"whois/internal/utils"
)

// TestLiveDNSQueries is an explicitly enabled, rate-limited public resolver test.
// It repeats a fixed corpus; it does not probe 10,000 distinct hosts.
func TestLiveDNSQueries(t *testing.T) {
	raw := os.Getenv("WHOIS_LIVE_DNS_QUERIES")
	if raw == "" {
		t.Skip("set WHOIS_LIVE_DNS_QUERIES=10000 to enable public DNS traffic")
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 1 || count > 10000 {
		t.Fatal("WHOIS_LIVE_DNS_QUERIES must be between 1 and 10000")
	}
	domains := []string{
		"example.com", "example.org", "iana.org", "icann.org", "w3.org", "ietf.org",
		"wikipedia.org", "wikimedia.org", "go.dev", "python.org", "mozilla.org", "cloudflare.com",
	}
	ips := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	types := []string{"A", "AAAA", "MX", "TXT"}
	resolver := NewDNSService("https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,https://dns.quad9.net/dns-query", "")
	t.Cleanup(resolver.httpClient.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond) // At most 40 lookups/second across all workers.
	defer ticker.Stop()
	type outcome struct {
		latency time.Duration
		kind    string
		err     error
	}
	results := make([]outcome, count)
	jobs := make(chan int)
	var workers sync.WaitGroup
	started := time.Now()
	for range 4 {
		workers.Go(func() {
			for i := range jobs {
				select {
				case <-ticker.C:
				case <-ctx.Done():
					results[i].err = ctx.Err()
					continue
				}
				target, kind, reverse := "", "PTR", i%5 == 4
				if reverse {
					target = ips[(i/5)%len(ips)]
				} else {
					target = domains[(i/5)%len(domains)]
					kind = types[i%5]
				}
				queryStarted := time.Now()
				queryCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				info := utils.NormalizeTarget(target)
				values, queryErr := resolver.LookupType(queryCtx, info.Host, kind, reverse)
				stop()
				if queryErr == nil && (kind == "A" || kind == "AAAA") {
					for _, value := range values {
						addr, parseErr := netip.ParseAddr(value)
						if parseErr != nil || addr.Is4() != (kind == "A") {
							queryErr = fmt.Errorf("%s answer contains invalid address %q", kind, value)
							break
						}
					}
				}
				if queryErr == nil && kind == "A" && len(values) == 0 {
					queryErr = fmt.Errorf("expected at least one A record for %s", target)
				}
				results[i] = outcome{time.Since(queryStarted), kind, queryErr}
			}
		})
	}
	for i := range count {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	latencies := make([]time.Duration, 0, count)
	failures := 0
	kinds := make(map[string]int)
	for i, result := range results {
		latencies = append(latencies, result.latency)
		kinds[result.kind]++
		if result.err != nil {
			failures++
			if failures <= 20 {
				t.Logf("query %d (%s): %v", i, result.kind, result.err)
			}
		}
	}
	slices.Sort(latencies)
	t.Logf("public DNS queries=%d completed=%d failures=%d mix=%v elapsed=%s p50=%s p95=%s p99=%s",
		count, count-failures, failures, kinds, time.Since(started), latencies[(count-1)*50/100], latencies[(count-1)*95/100], latencies[(count-1)*99/100])
	if failures > 0 {
		t.Fatalf("%d/%d public DNS queries failed; inspect resolver/network errors above", failures, count)
	}
}
