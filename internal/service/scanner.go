package service

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type ScanResult struct {
	Open    []int   `json:"open"`
	Closed  []int   `json:"closed"`
	Error   []string `json:"error,omitempty"`
	Elapsed float64 `json:"elapsed"`
}

func ScanPorts(target string, ports []int) ScanResult {
	start := time.Now()
	var res ScanResult
	res.Open = []int{}
	res.Closed = []int{}
	res.Error = []string{}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // Max concurrency 50

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			
			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			mu.Lock()
			if err != nil {
				// We consider connection refused or timeout as closed usually,
				// but strictly speaking they are different.
				// Python code treats them as closed unless it's a generic error.
				// Simplified: if err, closed.
				res.Closed = append(res.Closed, p)
			} else {
				conn.Close()
				res.Open = append(res.Open, p)
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	res.Elapsed = time.Since(start).Seconds()
	
	sort.Ints(res.Open)
	sort.Ints(res.Closed)
	
	return res
}
