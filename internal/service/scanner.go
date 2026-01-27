package service

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type ScanResult struct {
	Open    map[int]string `json:"open"` // Port -> Banner
	Closed  []int          `json:"closed"`
	Error   []string       `json:"error,omitempty"`
	Elapsed float64        `json:"elapsed"`
}

func ScanPortsStream(target string, ports []int, onResult func(port int, banner string, err error)) ScanResult {
	start := time.Now()
	var res ScanResult
	res.Open = make(map[int]string)
	res.Closed = []int{}
	res.Error = []string{}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := net.JoinHostPort(target, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)

			if err != nil {
				mu.Lock()
				res.Closed = append(res.Closed, p)
				mu.Unlock()
				if onResult != nil {
					onResult(p, "", err)
				}
			} else {
				defer func() {
					_ = conn.Close()
				}()

				// Attempt to grab banner
				_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				banner := make([]byte, 256)
				n, _ := conn.Read(banner)
				bannerStr := ""
				if n > 0 {
					bannerStr = string(banner[:n])
				}
				mu.Lock()
				res.Open[p] = bannerStr
				mu.Unlock()
				if onResult != nil {
					onResult(p, bannerStr, nil)
				}
			}
		}(port)
	}

	wg.Wait()
	res.Elapsed = time.Since(start).Seconds()
	sort.Ints(res.Closed)
	return res
}

func ScanPorts(target string, ports []int) ScanResult {
	return ScanPortsStream(target, ports, nil)
}
