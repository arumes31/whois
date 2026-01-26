package service

import (
	"net/http"
	"time"
)

type HTTPInfo struct {
	Status     string            `json:"status"`
	Protocol   string            `json:"protocol"`
	Headers    map[string]string `json:"headers"`
	Security   map[string]string `json:"security"`
	Error      string            `json:"error,omitempty"`
}

func GetHTTPInfo(host string) *HTTPInfo {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := "http://" + host
	resp, err := client.Get(url)
	if err != nil {
		// Try HTTPS if HTTP fails
		url = "https://" + host
		resp, err = client.Get(url)
		if err != nil {
			return &HTTPInfo{Error: err.Error()}
		}
	}
	defer resp.Body.Close()

	info := &HTTPInfo{
		Status:   resp.Status,
		Protocol: resp.Proto,
		Headers:  make(map[string]string),
		Security: make(map[string]string),
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
