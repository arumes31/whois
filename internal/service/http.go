package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
	"whois/internal/model"
	"whois/internal/utils"
)

func GetHTTPInfo(ctx context.Context, host string) *model.HTTPInfo {
	if !utils.IsValidTarget(host) {
		return &model.HTTPInfo{Error: "invalid target host"}
	}

	start := time.Now()
	var verified bool
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	targetURL := &url.URL{
		Scheme: "http",
		Host:   host,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return &model.HTTPInfo{Error: err.Error()}
	}

	resp, err := client.Do(req)
	if err != nil || (resp != nil && resp.StatusCode == http.StatusBadRequest) {
		// Try HTTPS if HTTP fails or returns 400 (which happens when talking HTTP to HTTPS port)
		if resp != nil {
			_ = resp.Body.Close()
		}
		targetURL.Scheme = "https"
		req, err = http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
		if err != nil {
			return &model.HTTPInfo{Error: err.Error()}
		}
		resp, err = client.Do(req)
		if err == nil {
			verified = true
		} else {
			// If HTTPS also fails (maybe due to invalid cert), we retry with skip verify
			// but mark it as unverified in the info
			verified = false
			tr := &http.Transport{
				// #nosec G402
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client.Transport = tr
			resp, err = client.Do(req)
			if err != nil {
				return &model.HTTPInfo{Error: fmt.Sprintf("HTTPS failed: %v", err)}
			}
		}
	} else {
		// If HTTP redirected to HTTPS, resp.TLS will be non-nil.
		if resp != nil && resp.TLS != nil {
			verified = true
		} else {
			verified = false
		}
	}
	defer func() {
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()

	elapsed := time.Since(start).Milliseconds()

	info := &model.HTTPInfo{
		Status:       resp.Status,
		Protocol:     resp.Proto,
		Headers:      make(map[string]string),
		Security:     make(map[string]string),
		ResponseTime: elapsed,
		Verified:     verified,
	}

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			info.Headers[k] = v[0]
		}
	}

	for _, h := range securityHeaders {
		if val, ok := info.Headers[h]; ok {
			info.Security[h] = val
		} else {
			info.Security[h] = "Not Set"
		}
	}

	return info
}
