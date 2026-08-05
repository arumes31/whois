package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"whois/internal/utils"
)

type ScanOptions struct {
	Concurrency    int
	MaxPorts       int
	ConnectTimeout time.Duration
	BannerTimeout  time.Duration
}

var PortPresets = map[string][]int{
	"web":      {80, 443, 8080, 8443, 8000, 8888},
	"mail":     {25, 110, 143, 465, 587, 993, 995},
	"database": {1433, 1521, 3306, 5432, 6379, 27017},
	"remote":   {22, 23, 3389, 5900, 5985, 5986},
	"common":   {20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017},
}

func DefaultScanOptions() ScanOptions {
	return ScanOptions{Concurrency: 32, MaxPorts: 1024, ConnectTimeout: 2 * time.Second, BannerTimeout: time.Second}
}

// ParsePortSpec accepts comma-separated ports, inclusive ranges, and named presets.
func ParsePortSpec(spec string, maxPorts int) ([]int, error) {
	if maxPorts <= 0 {
		return nil, fmt.Errorf("maximum port count must be positive")
	}
	seen := make(map[int]struct{})
	ports := make([]int, 0)
	add := func(port int) error {
		if port < 1 || port > 65535 {
			return fmt.Errorf("port %d is outside 1-65535", port)
		}
		if _, exists := seen[port]; exists {
			return nil
		}
		if len(ports) >= maxPorts {
			return fmt.Errorf("port selection exceeds the safe limit of %d", maxPorts)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
		return nil
	}

	for _, token := range strings.Split(strings.ToLower(spec), ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if preset, ok := PortPresets[token]; ok {
			for _, port := range preset {
				if err := add(port); err != nil {
					return nil, err
				}
			}
			continue
		}
		if strings.Count(token, "-") == 1 {
			bounds := strings.SplitN(token, "-", 2)
			start, startErr := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, endErr := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if startErr != nil || endErr != nil {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			if start > end {
				start, end = end, start
			}
			if end-start+1 > maxPorts {
				return nil, fmt.Errorf("port range %q exceeds the safe limit of %d", token, maxPorts)
			}
			for port := start; port <= end; port++ {
				if err := add(port); err != nil {
					return nil, err
				}
			}
			continue
		}
		port, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf("unknown port or preset %q", token)
		}
		if err := add(port); err != nil {
			return nil, err
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports selected")
	}
	sort.Ints(ports)
	return ports, nil
}

// ScanPortsStreamWithOptions scans the selected ports with bounded workers.
// onResult may be invoked concurrently by multiple workers; callers that share
// mutable callback state must synchronize it.
func ScanPortsStreamWithOptions(ctx context.Context, target string, ports []int, options ScanOptions, onResult func(port int, banner string, err error)) ScanResult {
	return scanPortsStreamWithOptions(ctx, target, ports, options, onResult, utils.ValidateResolvedHost, utils.DialResolvedTarget)
}

type scanResolver func(context.Context, string) ([]net.IPAddr, error)
type scanDialer func(context.Context, string, []net.IPAddr, string, time.Duration) (net.Conn, string, error)

func scanPortsStreamWithOptions(
	ctx context.Context,
	target string,
	ports []int,
	options ScanOptions,
	onResult func(port int, banner string, err error),
	resolve scanResolver,
	dial scanDialer,
) ScanResult {
	start := time.Now()
	result := ScanResult{Open: make(map[int]string), Closed: []int{}, Filtered: []int{}, Error: []string{}}
	targetInfo := utils.NormalizeTarget(target)
	if !targetInfo.Valid || !targetInfo.Networkable {
		result.Error = append(result.Error, "invalid target host")
		result.Elapsed = time.Since(start).Seconds()
		return result
	}
	if options.Concurrency < 1 {
		options.Concurrency = 1
	}
	if options.MaxPorts < 1 {
		options.MaxPorts = 1
	}
	if options.ConnectTimeout <= 0 {
		options.ConnectTimeout = 2 * time.Second
	}
	if options.BannerTimeout <= 0 {
		options.BannerTimeout = time.Second
	}
	if len(ports) > options.MaxPorts {
		result.Error = append(result.Error, fmt.Sprintf("port selection exceeds the safe limit of %d", options.MaxPorts))
		result.Elapsed = time.Since(start).Seconds()
		return result
	}
	validPorts := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			result.Error = append(result.Error, fmt.Sprintf("port %d is outside 1-65535", port))
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		validPorts = append(validPorts, port)
	}
	if err := ctx.Err(); err != nil {
		result.Error = append(result.Error, fmt.Sprintf("scan canceled: %v", err))
		result.Elapsed = time.Since(start).Seconds()
		return result
	}
	if len(validPorts) == 0 {
		result.Elapsed = time.Since(start).Seconds()
		return result
	}
	addresses, err := resolve(ctx, targetInfo.Host)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			result.Error = append(result.Error, fmt.Sprintf("scan canceled: %v", contextErr))
		} else {
			result.Error = append(result.Error, err.Error())
		}
		result.Elapsed = time.Since(start).Seconds()
		return result
	}
	if options.Concurrency > len(validPorts) {
		options.Concurrency = len(validPorts)
	}

	jobs := make(chan int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for port := range jobs {
			conn, _, err := dial(ctx, "tcp", addresses, strconv.Itoa(port), options.ConnectTimeout)
			if err != nil {
				if ctx.Err() != nil {
					if onResult != nil {
						onResult(port, "", ctx.Err())
					}
					return
				}
				mu.Lock()
				if isConnectionRefused(err) {
					result.Closed = append(result.Closed, port)
				} else {
					result.Filtered = append(result.Filtered, port)
				}
				mu.Unlock()
				if onResult != nil {
					onResult(port, "", err)
				}
				continue
			}
			bannerDeadline := time.Now().Add(options.BannerTimeout)
			if deadline, ok := ctx.Deadline(); ok && deadline.Before(bannerDeadline) {
				bannerDeadline = deadline
			}
			_ = conn.SetReadDeadline(bannerDeadline)
			stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
			bannerBytes := make([]byte, 256)
			n, _ := conn.Read(bannerBytes)
			stopCancel()
			_ = conn.Close()
			if ctx.Err() != nil {
				if onResult != nil {
					onResult(port, "", ctx.Err())
				}
				return
			}
			banner := ""
			if n > 0 {
				banner = strings.TrimSpace(string(bannerBytes[:n]))
			}
			mu.Lock()
			result.Open[port] = banner
			mu.Unlock()
			if onResult != nil {
				onResult(port, banner, nil)
			}
		}
	}
	for range options.Concurrency {
		wg.Add(1)
		go worker()
	}
	for _, port := range validPorts {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			result.Error = append(result.Error, fmt.Sprintf("scan canceled: %v", ctx.Err()))
			result.Elapsed = time.Since(start).Seconds()
			sort.Ints(result.Closed)
			sort.Ints(result.Filtered)
			return result
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		result.Error = append(result.Error, fmt.Sprintf("scan canceled: %v", err))
	}
	result.Elapsed = time.Since(start).Seconds()
	sort.Ints(result.Closed)
	sort.Ints(result.Filtered)
	return result
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// Windows can surface WSAECONNREFUSED through wrappers that do not retain a
	// portable errno for errors.Is. Keep the fallback narrow and only classify
	// the two standard refusal messages as closed.
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection refused") || strings.Contains(message, "actively refused")
}

// ScanPortsStream scans with default safety limits. onResult follows the same
// concurrent-callback contract as ScanPortsStreamWithOptions.
func ScanPortsStream(ctx context.Context, target string, ports []int, onResult func(port int, banner string, err error)) ScanResult {
	return ScanPortsStreamWithOptions(ctx, target, ports, DefaultScanOptions(), onResult)
}

func ScanPorts(ctx context.Context, target string, ports []int) ScanResult {
	return ScanPortsStream(ctx, target, ports, nil)
}
