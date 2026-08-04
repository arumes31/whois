package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
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

func ScanPortsStreamWithOptions(ctx context.Context, target string, ports []int, options ScanOptions, onResult func(port int, banner string, err error)) ScanResult {
	start := time.Now()
	result := ScanResult{Open: make(map[int]string), Closed: []int{}, Error: []string{}}
	targetInfo := utils.NormalizeTarget(target)
	if !targetInfo.Valid || !targetInfo.Networkable {
		result.Error = append(result.Error, "invalid target host")
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
		return result
	}
	if options.Concurrency > len(ports) {
		options.Concurrency = len(ports)
	}
	if options.Concurrency == 0 {
		return result
	}

	jobs := make(chan int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for port := range jobs {
			conn, _, err := utils.DialTarget(ctx, "tcp", targetInfo.Host, strconv.Itoa(port), options.ConnectTimeout)
			if err != nil {
				mu.Lock()
				result.Closed = append(result.Closed, port)
				mu.Unlock()
				if onResult != nil {
					onResult(port, "", err)
				}
				continue
			}
			_ = conn.SetReadDeadline(time.Now().Add(options.BannerTimeout))
			bannerBytes := make([]byte, 256)
			n, _ := conn.Read(bannerBytes)
			_ = conn.Close()
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
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			result.Elapsed = time.Since(start).Seconds()
			sort.Ints(result.Closed)
			return result
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	result.Elapsed = time.Since(start).Seconds()
	sort.Ints(result.Closed)
	return result
}

func ScanPortsStream(ctx context.Context, target string, ports []int, onResult func(port int, banner string, err error)) ScanResult {
	return ScanPortsStreamWithOptions(ctx, target, ports, DefaultScanOptions(), onResult)
}

func ScanPorts(ctx context.Context, target string, ports []int) ScanResult {
	return ScanPortsStream(ctx, target, ports, nil)
}
