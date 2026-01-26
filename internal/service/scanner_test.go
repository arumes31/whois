package service

import (
	"testing"
)

func TestScanPorts(t *testing.T) {
	// Scan localhost (assuming common ports might be closed/open)
	// We'll scan a known open port if possible, but 127.0.0.1 is safe.
	ports := []int{80, 443}
	res := ScanPorts("127.0.0.1", ports)
	
	if res.Elapsed <= 0 {
		t.Errorf("Elapsed time should be positive")
	}
	
	total := len(res.Open) + len(res.Closed)
	if total != len(ports) {
		t.Errorf("Expected %d total results, got %d", len(ports), total)
	}
}
