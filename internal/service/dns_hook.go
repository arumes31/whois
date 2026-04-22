package service

import (
	"context"
	"sync"
)

// DNSLookupFunc is a hook for mocking DNS lookups in tests.
var DNSLookupFunc func(ctx context.Context, target string, isIP bool) (map[string]interface{}, error)

func (s *DNSService) Lookup(ctx context.Context, target string, isIP bool) (map[string]interface{}, error) {
	if DNSLookupFunc != nil {
		return DNSLookupFunc(ctx, target, isIP)
	}
	results := make(map[string]interface{})
	var mu sync.Mutex
	err := s.LookupStream(ctx, target, isIP, func(rtype string, data interface{}) {
		mu.Lock()
		results[rtype] = data
		mu.Unlock()
	})
	return results, err
}
