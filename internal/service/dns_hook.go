package service

import (
	"context"
	"sync"

	"whois/internal/model"
)

// DNSLookupFunc is a hook for mocking DNS lookups in tests.
var DNSLookupFunc func(ctx context.Context, target string, isIP bool) (map[string]interface{}, error)

func (s *DNSService) Lookup(ctx context.Context, target string, isIP bool) (map[string]interface{}, error) {
	results, _, err := s.LookupDetailed(ctx, target, isIP)
	return results, err
}

// LookupDetailed returns legacy record arrays and their query evidence together.
func (s *DNSService) LookupDetailed(ctx context.Context, target string, isIP bool) (map[string]interface{}, model.DNSDetails, error) {
	if DNSLookupFunc != nil {
		results, err := DNSLookupFunc(ctx, target, isIP)
		return results, nil, err
	}
	results := make(map[string]interface{})
	details := make(model.DNSDetails)
	var mu sync.Mutex
	err := s.LookupStreamDetailed(ctx, target, isIP, func(name string, detail model.DNSQueryDetail) {
		mu.Lock()
		defer mu.Unlock()
		details[name] = detail
		for recordType, data := range DNSRecordResults(name, detail) {
			results[recordType] = data
		}
	})
	return results, details, err
}
