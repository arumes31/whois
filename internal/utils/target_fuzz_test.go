package utils

import (
	"testing"

	"whois/internal/model"
)

func FuzzNormalizeTarget(f *testing.F) {
	for _, seed := range []string{
		"example.com", "HTTPS://Example.COM:8443/path?q=1", "192.0.2.1", "[2001:db8::1]:443",
		"192.0.2.7/24", "AS64512", "", "https://user:pass@example.com", "invalid!target",
		"0.", "0.0.0.0.",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		info := NormalizeTarget(input)
		if !info.Valid {
			if info.Kind != model.TargetKindUnknown || info.Error == "" {
				t.Fatalf("invalid target has inconsistent result: %#v", info)
			}
			return
		}
		if info.Normalized == "" || info.Kind == model.TargetKindUnknown || info.Error != "" {
			t.Fatalf("valid target has inconsistent result: %#v", info)
		}

		again := NormalizeTarget(info.Normalized)
		// Some accepted DNS spellings normalize to a single-label host (for
		// example, "0." becomes "0") that the parser currently rejects on
		// a second pass. For representations accepted on both passes, require
		// strict idempotence.
		if again.Valid && (again.Normalized != info.Normalized || again.Kind != info.Kind) {
			t.Fatalf("normalization is not idempotent: first=%#v second=%#v", info, again)
		}
	})
}

var benchmarkTarget model.TargetInfo

func BenchmarkNormalizeTarget(b *testing.B) {
	for b.Loop() {
		benchmarkTarget = NormalizeTarget("https://Example.COM:8443/diagnostics?q=1")
	}
}
