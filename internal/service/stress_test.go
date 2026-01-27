//go:build stress

package service

import (
	"sync"
	"testing"
)

func TestStressPortScanner(t *testing.T) {
	target := "127.0.0.1"
	ports := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		ports[i] = i + 1
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanPorts(target, ports)
		}()
	}
	wg.Wait()
}

func TestStressDNSLookup(t *testing.T) {
	s := NewDNSService()
	target := "google.com"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Lookup(target, false)
		}()
	}
	wg.Wait()
}
