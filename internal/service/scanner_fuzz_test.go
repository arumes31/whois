package service

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func FuzzParsePortSpec(f *testing.F) {
	for _, seed := range []string{"80", "web,22", "8000-8002,443", "1,65535", "", "0", "1-65535"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePortSpec(spec, 128)
		if err != nil {
			return
		}
		if len(ports) == 0 || len(ports) > 128 {
			t.Fatalf("successful parse returned %d ports", len(ports))
		}
		if !slices.IsSorted(ports) {
			t.Fatalf("ports are not sorted: %v", ports)
		}
		for index, port := range ports {
			if port < 1 || port > 65535 {
				t.Fatalf("port outside valid range: %d", port)
			}
			if index > 0 && ports[index-1] == port {
				t.Fatalf("duplicate port: %d", port)
			}
		}

		roundTrip := make([]string, len(ports))
		for index, port := range ports {
			roundTrip[index] = strconv.Itoa(port)
		}
		parsedAgain, err := ParsePortSpec(strings.Join(roundTrip, ","), 128)
		if err != nil || !slices.Equal(parsedAgain, ports) {
			t.Fatalf("round trip = %v, %v; want %v", parsedAgain, err, ports)
		}
	})
}

var benchmarkPorts []int

func BenchmarkParsePortSpec(b *testing.B) {
	for b.Loop() {
		ports, err := ParsePortSpec("web,22,53,8000-8100,8443", 128)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkPorts = ports
	}
}
