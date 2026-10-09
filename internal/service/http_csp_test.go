package service

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func securityResponse(csp ...string) *http.Response {
	return &http.Response{
		Header: http.Header{
			"Content-Security-Policy":   csp,
			"Strict-Transport-Security": {"max-age=31536000"},
			"Permissions-Policy":        {"geolocation=()"},
			"X-Content-Type-Options":    {"nosniff"},
			"X-Frame-Options":           {"DENY"},
			"Referrer-Policy":           {"no-referrer"},
		},
		Request: &http.Request{URL: &url.URL{Scheme: "https", Host: "example.test"}},
	}
}

func TestCSPUnsafeScriptExecution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []string
		unsafe   bool
	}{
		{"style only", []string{"default-src 'self'; style-src 'unsafe-inline'"}, false},
		{"style eval only", []string{"default-src 'self'; style-src 'unsafe-eval'"}, false},
		{"script inline", []string{"default-src 'self'; script-src 'unsafe-inline'"}, true},
		{"script eval", []string{"default-src 'self'; script-src 'unsafe-eval'"}, true},
		{"default fallback", []string{"default-src 'unsafe-inline'"}, true},
		{"overridden default", []string{"default-src 'unsafe-inline'; script-src 'self'"}, false},
		{"script element", []string{"default-src 'none'; script-src-elem 'unsafe-inline'"}, true},
		{"script attribute", []string{"default-src 'none'; script-src-attr 'unsafe-inline'"}, true},
		{"both overrides", []string{"default-src 'self'; script-src 'unsafe-inline'; script-src-elem 'none'; script-src-attr 'none'"}, false},
		{"eval element ignored", []string{"default-src 'self'; script-src-elem 'unsafe-eval'"}, false},
		{"nonce overrides inline", []string{"default-src 'self'; script-src 'unsafe-inline' 'nonce-YWJjZA=='"}, false},
		{"hash overrides inline", []string{"default-src 'self'; script-src 'unsafe-inline' 'sha256-YWJjZA=='"}, false},
		{"strict dynamic overrides inline", []string{"default-src 'self'; script-src 'unsafe-inline' 'strict-dynamic'"}, false},
		{"nonce does not override eval", []string{"default-src 'self'; script-src 'unsafe-eval' 'nonce-YWJjZA=='"}, true},
		{"case insensitive", []string{"DEFAULT-SRC 'self'; SCRIPT-SRC 'UNSAFE-INLINE'"}, true},
		{"first duplicate wins", []string{"default-src 'self'; script-src 'none'; script-src 'unsafe-inline'"}, false},
		{"header intersection", []string{"default-src 'self'; script-src 'unsafe-inline'", "script-src 'none'"}, false},
		{"comma intersection", []string{"default-src 'self'; script-src 'unsafe-inline', script-src 'none'"}, false},
		{"unrelated second policy", []string{"default-src 'self'; script-src 'unsafe-inline'", "img-src 'self'"}, true},
		{"token substring", []string{"default-src 'self'; report-uri https://example.test/unsafe-inline"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, issues, score := inspectHTTPSecurity(securityResponse(tc.policies...), "")
			got := slices.Contains(issues, "content security policy allows unsafe script execution")
			if got != tc.unsafe {
				t.Fatalf("unsafe script finding = %v; want %v; issues=%v", got, tc.unsafe, issues)
			}
			wantScore := 100
			if tc.unsafe {
				wantScore = 90
			}
			if score != wantScore {
				t.Fatalf("score = %d; want %d", score, wantScore)
			}
		})
	}
}

func TestCSPFrameAncestorsReplacesXFO(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policies   []string
		reportOnly string
		protected  bool
	}{
		{"none", []string{"default-src 'self'; frame-ancestors 'none'"}, "", true},
		{"self", []string{"default-src 'self'; frame-ancestors 'self'"}, "", true},
		{"allowlist", []string{"default-src 'self'; frame-ancestors https://embed.example.test"}, "", true},
		{"subdomain allowlist", []string{"default-src 'self'; frame-ancestors https://*.example.test"}, "", true},
		{"second enforced header", []string{"default-src 'self'", "frame-ancestors 'none'"}, "", true},
		{"case insensitive", []string{"DEFAULT-SRC 'self'; FRAME-ANCESTORS 'SELF'"}, "", true},
		{"report only", []string{"default-src 'self'"}, "frame-ancestors 'none'", false},
		{"frame src unrelated", []string{"default-src 'self'; frame-src 'none'"}, "", false},
		{"default unrelated", []string{"default-src 'none'"}, "", false},
		{"wildcard", []string{"default-src 'self'; frame-ancestors *"}, "", false},
		{"scheme wildcard", []string{"default-src 'self'; frame-ancestors https:"}, "", false},
		{"host wildcard", []string{"default-src 'self'; frame-ancestors https://*"}, "", false},
		{"first duplicate wins", []string{"default-src 'self'; frame-ancestors *; frame-ancestors 'none'"}, "", false},
		{"restrictive intersection", []string{"default-src 'self'; frame-ancestors *", "frame-ancestors 'self'"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := securityResponse(tc.policies...)
			response.Header.Del("X-Frame-Options")
			if tc.reportOnly != "" {
				response.Header.Set("Content-Security-Policy-Report-Only", tc.reportOnly)
			}
			checks, _, issues, score := inspectHTTPSecurity(response, "")
			want := 90
			if tc.protected {
				want = 100
			}
			if score != want {
				t.Fatalf("score = %d; want %d; issues=%v", score, want, issues)
			}
			if tc.protected {
				for _, check := range checks {
					if check.Name == "X-Frame-Options" && check.Status != "not-applicable" {
						t.Fatalf("XFO status = %q despite enforced frame-ancestors", check.Status)
					}
				}
				for _, issue := range issues {
					if strings.Contains(issue, "X-Frame-Options") {
						t.Fatalf("unexpected XFO issue: %s", issue)
					}
				}
			}
		})
	}
}

func TestCSPDefaultSourceRecommendationUsesDirectives(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policies  []string
		wantScore int
	}{
		{"second enforced policy", []string{"script-src 'self'", "default-src 'none'"}, 100},
		{"empty first header", []string{"", "default-src 'none'"}, 100},
		{"case insensitive", []string{"DEFAULT-SRC 'none'"}, 100},
		{"URL substring", []string{"report-uri https://example.test/default-src"}, 92},
		{"different directive", []string{"not-default-src 'self'"}, 92},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, issues, score := inspectHTTPSecurity(securityResponse(tc.policies...), "")
			if score != tc.wantScore {
				t.Fatalf("score=%d; want %d; issues=%v", score, tc.wantScore, issues)
			}
		})
	}
}
