package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"whois/internal/utils"
)

func TestHTTPProbeTargetAuthority(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input string
		url   string
	}{
		{"2001:4860:4860::8888", "https://[2001:4860:4860::8888]"},
		{"[2001:4860:4860::8888]", "https://[2001:4860:4860::8888]"},
		{"https://[2001:4860:4860::8888]/path?q=1", "https://[2001:4860:4860::8888]"},
		{"http://[2001:4860:4860::8888]/path?q=1", "http://[2001:4860:4860::8888]"},
		{"[2001:4860:4860::8888]:8443", "https://[2001:4860:4860::8888]:8443"},
		{"https://[2001:4860:4860::8888]:443", "https://[2001:4860:4860::8888]:443"},
		{"http://[2001:4860:4860::8888]:80", "http://[2001:4860:4860::8888]:80"},
		{"http://[2001:4860:4860::8888]:8080/a", "http://[2001:4860:4860::8888]:8080"},
		{"8.8.8.8", "https://8.8.8.8"},
		{"8.8.8.8:8443", "https://8.8.8.8:8443"},
		{"https://Example.COM/path?q=1", "https://example.com"},
		{"http://example.com:8080/a", "http://example.com:8080"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			profile := utils.NormalizeTarget(tc.input)
			if !profile.Valid {
				t.Fatalf("invalid target: %+v", profile)
			}
			requests := 0
			client := &http.Client{Transport: httpTargetTransport(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.String() != tc.url || req.URL.Hostname() != profile.Host || req.URL.Port() != profile.Port {
					t.Errorf("outbound request = %q (host %q port %q); want %q (host %q port %q)", req.URL, req.URL.Hostname(), req.URL.Port(), tc.url, profile.Host, profile.Port)
				}
				return &http.Response{StatusCode: http.StatusOK, Request: req, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			_, err := probeHTTPTarget(context.Background(), profile, func(ctx context.Context, targetURL string, insecure bool) (*httpProbe, error) {
				if insecure {
					t.Error("initial request unexpectedly skips certificate verification")
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
				if err != nil {
					return nil, err
				}
				resp, err := client.Do(req)
				if err == nil {
					_ = resp.Body.Close()
				}
				return &httpProbe{response: resp}, err
			})
			if err != nil || requests != 1 {
				t.Fatalf("probe returned %v after %d requests", err, requests)
			}
		})
	}
}

func TestHTTPProbeTargetFallbackKeepsIPv6Authority(t *testing.T) {
	t.Parallel()
	profile := utils.NormalizeTarget("2001:4860:4860::8888")
	var calls []string
	_, err := probeHTTPTarget(context.Background(), profile, func(_ context.Context, targetURL string, insecure bool) (*httpProbe, error) {
		calls = append(calls, fmt.Sprintf("%s insecure=%t", targetURL, insecure))
		return nil, fmt.Errorf("fixture transport unavailable")
	})
	want := "https://[2001:4860:4860::8888] insecure=false\nhttps://[2001:4860:4860::8888] insecure=true\nhttp://[2001:4860:4860::8888] insecure=false"
	if err == nil || strings.Join(calls, "\n") != want {
		t.Fatalf("fallback calls = %v, error = %v", calls, err)
	}
}

type httpTargetTransport func(*http.Request) (*http.Response, error)

func (f httpTargetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
