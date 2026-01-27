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

func ScanPorts(target string, ports []int) ScanResult {
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

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				res.Closed = append(res.Closed, p)
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
				res.Open[p] = bannerStr
			}
		}(port)
	}

	wg.Wait()
	res.Elapsed = time.Since(start).Seconds()

	sort.Ints(res.Closed)

	return res
}
