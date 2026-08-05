package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"whois/internal/model"
	"whois/internal/utils"
)

const (
	httpTimeout  = 8 * time.Second
	maxHTTPBody  = 1024 * 1024
	maxRedirects = 10
)

type httpProbe struct {
	response  *http.Response
	body      string
	timing    model.HTTPTiming
	redirects []model.HTTPRedirect
	remoteIP  string
	verified  bool
}

func GetHTTPInfo(ctx context.Context, target string) *model.HTTPInfo {
	targetInfo := utils.NormalizeTarget(target)
	if !targetInfo.Valid || !targetInfo.Networkable {
		return &model.HTTPInfo{Error: "invalid target host"}
	}

	hostPort := targetInfo.Host
	if targetInfo.Port != "" {
		hostPort = net.JoinHostPort(targetInfo.Host, targetInfo.Port)
	}

	type probeCandidate struct {
		scheme   string
		insecure bool
	}
	candidates := []probeCandidate{{"https", false}, {"https", true}, {"http", false}}
	switch targetInfo.Scheme {
	case "https":
		candidates = candidates[:2]
	case "http":
		candidates = candidates[2:]
	}
	var probe *httpProbe
	var err error
	for _, candidate := range candidates {
		probe, err = doHTTPProbe(ctx, candidate.scheme+"://"+hostPort, candidate.insecure)
		if err == nil && probe != nil && probe.response != nil {
			break
		}
	}
	if err != nil {
		return &model.HTTPInfo{Error: fmt.Sprintf("http probe failed: %v", err)}
	}

	resp := probe.response
	compression := resp.Header.Get("Content-Encoding")
	if compression == "" && resp.Uncompressed {
		compression = "gzip"
	}
	info := &model.HTTPInfo{
		Status: resp.Status, Protocol: resp.Proto, Headers: make(map[string]string), Security: make(map[string]string),
		ResponseTime: probe.timing.Total, IP: probe.remoteIP, Verified: probe.verified,
		FinalURL: resp.Request.URL.String(), Redirects: probe.redirects, Timing: probe.timing,
		Compression: compression, ContentType: resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength, Server: resp.Header.Get("Server"), PoweredBy: resp.Header.Get("X-Powered-By"),
		DirectoryListing: looksLikeDirectoryListing(probe.body),
	}
	for key, values := range resp.Header {
		info.Headers[key] = strings.Join(values, ", ")
	}
	info.Cookies = inspectCookies(resp.Cookies())
	info.SecurityChecks, info.Security, info.Issues, info.Score = inspectHTTPSecurity(resp, probe.body)
	info.Grade = gradeForScore(info.Score)
	info.CORS = inspectCORS(resp.Header)
	info.AllowedMethods = probeAllowedMethods(ctx, resp.Request.URL)
	info.RobotsTXT = probeWellKnown(ctx, resp.Request.URL, "/robots.txt")
	info.SecurityTXT = probeWellKnown(ctx, resp.Request.URL, "/.well-known/security.txt")
	return info
}

func doHTTPProbe(ctx context.Context, targetURL string, insecure bool) (*httpProbe, error) {
	u, err := url.Parse(targetURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid target url")
	}
	probe := &httpProbe{verified: u.Scheme == "https" && !insecure}
	var traceMu sync.Mutex
	var traceTiming model.HTTPTiming
	var dnsStart, tlsStart time.Time
	connectStarts := make(map[string]time.Time)
	var dnsDone, connectDone, tlsDone bool
	var remoteIP string
	var requestStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			traceMu.Lock()
			if dnsStart.IsZero() {
				dnsStart = time.Now()
			}
			traceMu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			traceMu.Lock()
			if !dnsDone && !dnsStart.IsZero() {
				traceTiming.DNS = time.Since(dnsStart).Milliseconds()
				dnsDone = true
			}
			traceMu.Unlock()
		},
		ConnectStart: func(network, address string) {
			traceMu.Lock()
			connectStarts[network+"\x00"+address] = time.Now()
			traceMu.Unlock()
		},
		ConnectDone: func(network, address string, connectErr error) {
			traceMu.Lock()
			key := network + "\x00" + address
			started := connectStarts[key]
			delete(connectStarts, key)
			if !connectDone && connectErr == nil && !started.IsZero() {
				traceTiming.Connect = time.Since(started).Milliseconds()
				connectDone = true
			}
			traceMu.Unlock()
		},
		TLSHandshakeStart: func() {
			traceMu.Lock()
			if tlsStart.IsZero() {
				tlsStart = time.Now()
			}
			traceMu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			traceMu.Lock()
			if !tlsDone && !tlsStart.IsZero() {
				traceTiming.TLS = time.Since(tlsStart).Milliseconds()
				tlsDone = true
			}
			traceMu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if host, _, splitErr := net.SplitHostPort(info.Conn.RemoteAddr().String()); splitErr == nil {
				traceMu.Lock()
				remoteIP = host
				traceMu.Unlock()
			}
		},
		GotFirstResponseByte: func() {
			traceMu.Lock()
			traceTiming.TTFB = time.Since(requestStart).Milliseconds()
			traceMu.Unlock()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "whois-diagnostics/1.0")

	transport := safeHTTPTransport(insecure)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect uses unsupported scheme")
			}
			if _, err := utils.ValidateResolvedHost(req.Context(), req.URL.Hostname()); err != nil {
				return fmt.Errorf("unsafe redirect: %w", err)
			}
			if req.Response != nil {
				probe.redirects = append(probe.redirects, model.HTTPRedirect{Status: req.Response.StatusCode, URL: req.Response.Request.URL.String(), Location: req.URL.String()})
			}
			return nil
		},
	}
	// The transport resolves, validates, and pins every destination (including
	// redirects) before dialing, so user input cannot reach a disallowed network.
	requestStart = time.Now()
	resp, err := client.Do(req) // lgtm[go/request-forgery]
	traceMu.Lock()
	probe.timing = traceTiming
	probe.remoteIP = remoteIP
	traceMu.Unlock()
	probe.timing.Total = time.Since(requestStart).Milliseconds()
	if err != nil {
		return probe, err
	}
	probe.verified = resp.TLS != nil && !insecure
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return probe, fmt.Errorf("read response: %w", readErr)
	}
	probe.response, probe.body = resp, string(body)
	return probe, nil
}

func safeHTTPTransport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, // #nosec G402 -- diagnostic fallback, surfaced as unverified
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			conn, _, err := utils.DialTarget(ctx, network, host, port, httpTimeout)
			return conn, err
		},
	}
}

func inspectHTTPSecurity(resp *http.Response, body string) ([]model.SecurityCheck, map[string]string, []string, int) {
	headers := []struct{ name, guidance string }{
		{"Strict-Transport-Security", "enable HSTS on HTTPS responses"},
		{"Content-Security-Policy", "define a restrictive content security policy"},
		{"Permissions-Policy", "disable browser capabilities that are not needed"},
		{"X-Content-Type-Options", "set to nosniff"},
		{"X-Frame-Options", "set DENY or SAMEORIGIN, or use CSP frame-ancestors"},
		{"Referrer-Policy", "set an explicit referrer policy"},
	}
	checks := make([]model.SecurityCheck, 0, len(headers)+1)
	legacy := make(map[string]string, len(headers))
	issues := make([]string, 0)
	score := 100
	for _, header := range headers {
		value, status := resp.Header.Get(header.name), "pass"
		legacy[header.name] = value
		if header.name == "Strict-Transport-Security" && resp.Request.URL.Scheme != "https" {
			status = "not-applicable"
			if value == "" {
				legacy[header.name] = "Not applicable on HTTP"
			}
		} else if value == "" {
			legacy[header.name], status = "Not Set", "missing"
			score -= 10
			issues = append(issues, header.name+" is not set")
		} else if problem := invalidSecurityHeader(header.name, value); problem != "" {
			status = "warning"
			score -= 8
			issues = append(issues, problem)
		}
		checks = append(checks, model.SecurityCheck{Name: header.name, Status: status, Value: value, Guidance: header.guidance})
	}
	if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		score -= 10
		issues = append(issues, "content security policy allows unsafe script execution")
		checks = append(checks, model.SecurityCheck{Name: "CSP quality", Status: "warning", Value: csp, Guidance: "remove unsafe-inline and unsafe-eval where possible"})
	}
	if resp.Request.URL.Scheme == "https" && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") && mixedContentPattern.MatchString(body) {
		score -= 8
		issues = append(issues, "response may contain mixed HTTP content")
	}
	if cors := inspectCORS(resp.Header); strings.Contains(cors, "unsafe") {
		score -= 15
		issues = append(issues, cors)
	}
	for _, cookie := range resp.Cookies() {
		if resp.Request.URL.Scheme == "https" && !cookie.Secure {
			score -= 5
			issues = append(issues, "cookie "+cookie.Name+" is missing the Secure attribute")
		}
		if !cookie.HttpOnly {
			score -= 3
			issues = append(issues, "cookie "+cookie.Name+" is accessible to scripts")
		}
	}
	if score < 0 {
		score = 0
	}
	return checks, legacy, issues, score
}

var mixedContentPattern = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']http://`)

func invalidSecurityHeader(name, value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch name {
	case "Strict-Transport-Security":
		for _, directive := range strings.Split(lower, ";") {
			key, raw, found := strings.Cut(strings.TrimSpace(directive), "=")
			if key != "max-age" || !found {
				continue
			}
			seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err == nil && seconds > 0 {
				return ""
			}
		}
		return "Strict-Transport-Security has no positive max-age"
	case "X-Content-Type-Options":
		if lower != "nosniff" {
			return "X-Content-Type-Options must be nosniff"
		}
	case "X-Frame-Options":
		if lower != "deny" && lower != "sameorigin" {
			return "X-Frame-Options must be DENY or SAMEORIGIN"
		}
	case "Content-Security-Policy":
		if !strings.Contains(lower, "default-src") {
			return "Content-Security-Policy should define default-src"
		}
	}
	return ""
}

func inspectCookies(cookies []*http.Cookie) []model.CookieInfo {
	result := make([]model.CookieInfo, 0, len(cookies))
	for _, cookie := range cookies {
		sameSite := "unspecified"
		switch cookie.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		result = append(result, model.CookieInfo{Name: cookie.Name, Secure: cookie.Secure, HTTPOnly: cookie.HttpOnly, SameSite: sameSite})
	}
	return result
}

func inspectCORS(headers http.Header) string {
	origin := headers.Get("Access-Control-Allow-Origin")
	credentials := strings.EqualFold(headers.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case origin == "*" && credentials:
		return "unsafe wildcard origin with credentials"
	case origin == "*":
		return "wildcard origin"
	case origin != "":
		return "restricted to " + origin
	default:
		return "not advertised"
	}
}

func probeAllowedMethods(ctx context.Context, base *url.URL) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, base.String(), nil)
	if err != nil {
		return nil
	}
	transport := safeHTTPTransport(false)
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 4 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	methods := strings.FieldsFunc(resp.Header.Get("Allow"), func(r rune) bool { return r == ',' || r == ' ' })
	for i := range methods {
		methods[i] = strings.ToUpper(methods[i])
	}
	sort.Strings(methods)
	return methods
}

func probeWellKnown(ctx context.Context, base *url.URL, path string) string {
	u := *base
	u.Path, u.RawQuery, u.Fragment = path, "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "unavailable"
	}
	transport := safeHTTPTransport(false)
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 4 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "unavailable"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "present"
	}
	return fmt.Sprintf("not found (%d)", resp.StatusCode)
}

func looksLikeDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<title>index of /") || strings.Contains(lower, "<h1>index of /") || strings.Contains(lower, "parent directory</a>")
}
