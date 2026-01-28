package service

import (
	"net"
	"strings"
	"testing"
)

func TestScanPorts(t *testing.T) {
	// Scan localhost (assuming common ports might be closed/open)
	// We'll scan a known open port if possible, but 127.0.0.1 is safe.
	ports := []int{80, 443}
	res := ScanPorts("127.0.0.1", ports)

	if res.Elapsed < 0 {
		t.Errorf("Elapsed time should be non-negative")
	}

	total := len(res.Open) + len(res.Closed)
	if total != len(ports) {
		t.Errorf("Expected %d total results, got %d", len(ports), total)
	}
}

func TestScanPorts_Open(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	host := "127.0.0.1"

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("test banner"))
			_ = conn.Close()
		}
	}()

	res := ScanPorts(host, []int{port})
	if _, ok := res.Open[port]; !ok {
		t.Errorf("Expected port %d to be open", port)
	}
	if !strings.Contains(res.Open[port], "test banner") {
		t.Errorf("Expected banner 'test banner', got '%s'", res.Open[port])
	}
}

func TestScanPortsStream(t *testing.T) {
	ports := []int{80, 443}
	count := 0
	ScanPortsStream("127.0.0.1", ports, func(port int, banner string, err error) {
		count++
	})

	if count != len(ports) {
		t.Errorf("Expected %d callbacks, got %d", len(ports), count)
	}
}
