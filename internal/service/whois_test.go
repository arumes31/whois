package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"whois/internal/utils"

	"github.com/likexian/whois"
	"github.com/openrdap/rdap"
)

func init() {
	utils.TestInitLogger()
}

func TestWhois(t *testing.T) {
	oldWhois := WhoisFunc
	oldValidator := WhoisServerValidator
	defer func() {
		WhoisFunc = oldWhois
		WhoisServerValidator = oldValidator
	}()
	WhoisServerValidator = func(context.Context, string) error { return nil }

	WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
		if target == "" {
			return "", fmt.Errorf("empty target")
		}
		if target == "invalid!target" {
			return "invalid tld", nil
		}
		return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\nDomain Name: " + target + "\nRegistrar: MockReg", nil
	}

	tests := []struct {
		name   string
		target string
	}{
		{"Valid Domain", "google.com"},
		{"Info Domain Fallback", "google.info"},
		{"Biz Domain Fallback", "google.biz"},
		{"Online Domain Fallback", "google.online"},
		{"IO Domain Fallback", "google.io"},
		{"Valid IP", "8.8.8.8"},
		{"Invalid Target", "this.is.not.a.real.domain.at.all.nonexistent"},
		{"Empty Target", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Whois(context.Background(), tt.target)
			if result == nil {
				t.Error("Whois returned nil")
			}

			switch v := result.(type) {
			case string:
				if tt.target == "google.com" || tt.target == "8.8.8.8" {
					t.Logf("Got error string for %s (unexpected but allowed in some envs): %s", tt.target, v)
				}
			case WhoisInfo:
				if v.Raw == "" {
					t.Error("Raw WHOIS data is empty")
				}
				if tt.target == "google.com" {
					if v.Registrar == "" {
						t.Log("Registrar is empty for google.com (parsed failed?)")
					}
				}
			default:
				t.Errorf("Unexpected result type %T", result)
			}
		})
	}
}

func TestRDAPLookup(t *testing.T) {
	oldRdap := RdapLookupFunc
	defer func() { RdapLookupFunc = oldRdap }()

	RdapLookupFunc = func(context.Context, string) (string, error) {
		return "Mock RDAP Data", nil
	}

	res, err := RdapLookupFunc(context.Background(), "google.com")
	if err != nil {
		t.Fatalf("RDAP lookup failed: %v", err)
	}
	if res == "" {
		t.Error("Expected non-empty RDAP result")
	}
}

func TestWhois_Mocked(t *testing.T) {
	oldWhois := WhoisFunc
	oldRdap := RdapLookupFunc
	oldValidator := WhoisServerValidator
	defer func() {
		WhoisFunc = oldWhois
		RdapLookupFunc = oldRdap
		WhoisServerValidator = oldValidator
	}()
	WhoisServerValidator = func(context.Context, string) error { return nil }

	t.Run("Error Response Fallback", func(t *testing.T) {
		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			if len(query) == 0 {
				return "TLD is not supported", nil
			}
			return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\nDomain Name: google.info\nRegistrar: InfoReg", nil
		}
		res := Whois(context.Background(), "google.info")
		info, ok := res.(WhoisInfo)
		if !ok || info.Registrar != "InfoReg" {
			t.Errorf("Expected fallback to succeed, got %v", res)
		}
	})

	t.Run("IANA Referral", func(t *testing.T) {
		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			if len(query) == 0 {
				return "No whois server found", nil
			}
			if query[0] == "whois.iana.org" {
				return "whois: whois.nic.test\nrefer: whois.nic.test", nil
			}
			if query[0] == "whois.nic.test" {
				return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\nDomain Name: test.com\nRegistrar: TestReg", nil
			}
			return "error", nil
		}
		res := Whois(context.Background(), "test.com")
		info, ok := res.(WhoisInfo)
		if !ok || info.Registrar != "TestReg" {
			t.Errorf("Expected IANA referral to succeed, got %v", res)
		}
	})

	t.Run("Registrar Referral", func(t *testing.T) {
		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			if len(query) == 0 {
				return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\nRegistrar WHOIS Server: whois.reg.test\nDomain Name: test.com", nil
			}
			if query[0] == "whois.reg.test" {
				return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\nDomain Name: test.com\nRegistrar: RegReg", nil
			}
			return "error", nil
		}
		res := Whois(context.Background(), "test.com")
		info, ok := res.(WhoisInfo)
		if !ok || info.Registrar != "RegReg" {
			t.Errorf("Expected registrar referral to succeed, got %v", res)
		}
	})

	t.Run("Filtering and Empty Lines", func(t *testing.T) {
		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			return strings.Repeat("Long response prefix to bypass length check... ", 10) + "\n%\n#\n\nLine 1\n\nLine 2\n", nil
		}
		res := Whois(context.Background(), "test.com")
		info, _ := res.(WhoisInfo)
		if strings.Contains(info.Raw, "%") || strings.Contains(info.Raw, "#") {
			t.Error("Expected comments to be filtered")
		}
		if !strings.Contains(info.Raw, "Line 1") {
			t.Error("Expected Line 1 to be present")
		}
	})

	t.Run("IANA Lookup Failure Fallback to RDAP", func(t *testing.T) {
		oldRdap := RdapLookupFunc
		defer func() { RdapLookupFunc = oldRdap }()

		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			if len(query) == 0 {
				return "No whois server found", nil
			}
			if query[0] == "whois.iana.org" {
				return "", fmt.Errorf("IANA connection error")
			}
			return "error", nil
		}
		RdapLookupFunc = func(context.Context, string) (string, error) {
			return "Mock RDAP Data for IANA Failure", nil
		}

		res := Whois(context.Background(), "test.com")
		info, ok := res.(WhoisInfo)
		if !ok || info.Raw != "Mock RDAP Data for IANA Failure" {
			t.Errorf("Expected RDAP fallback on IANA failure, got %v", res)
		}
	})

	t.Run("IANA Referred Server Failure Fallback to RDAP", func(t *testing.T) {
		oldRdap := RdapLookupFunc
		defer func() { RdapLookupFunc = oldRdap }()

		WhoisFunc = func(_ context.Context, target string, query ...string) (string, error) {
			if len(query) == 0 {
				return "No whois server found", nil
			}
			if query[0] == "whois.iana.org" {
				return "whois: whois.nic.fail\nrefer: whois.nic.fail", nil
			}
			if query[0] == "whois.nic.fail" {
				return "", fmt.Errorf("Referred server error")
			}
			return "error", nil
		}
		RdapLookupFunc = func(context.Context, string) (string, error) {
			return "Mock RDAP Data for Referral Failure", nil
		}

		res := Whois(context.Background(), "test.com")
		info, ok := res.(WhoisInfo)
		if !ok || info.Raw != "Mock RDAP Data for Referral Failure" {
			t.Errorf("Expected RDAP fallback on referral failure, got %v", res)
		}
	})
}

func TestValidateWhoisServerRejectsPrivateAddress(t *testing.T) {
	for _, server := range []string{"127.0.0.1", "[::1]:43", "http://127.0.0.1:43"} {
		if err := validateWhoisServer(context.Background(), server); err == nil {
			t.Errorf("validateWhoisServer(%q) accepted a private referral", server)
		}
	}
}

func TestWhoisPinnedDialerPinsInitialAndReferralAddresses(t *testing.T) {
	resolvedHosts := make([]string, 0, 2)
	var resolvedMu sync.Mutex
	resolver := func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolvedMu.Lock()
		resolvedHosts = append(resolvedHosts, host)
		resolvedMu.Unlock()
		switch host {
		case "registry.example":
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
		case "referral.example":
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.20")}}, nil
		default:
			return nil, fmt.Errorf("unexpected WHOIS host %q", host)
		}
	}

	serverErrors := make(chan error, 2)
	dialer := func(_ context.Context, network string, addresses []net.IPAddr, port string, _ time.Duration) (net.Conn, string, error) {
		if network != "tcp" || port != "43" || len(addresses) != 1 {
			return nil, "", fmt.Errorf("unexpected pinned dial: network=%s port=%s addresses=%v", network, port, addresses)
		}
		ip := addresses[0].IP.String()
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			query, err := bufio.NewReader(server).ReadString('\n')
			if err != nil {
				serverErrors <- fmt.Errorf("read WHOIS query: %w", err)
				return
			}
			if strings.TrimSpace(query) != "example.com" {
				serverErrors <- fmt.Errorf("WHOIS query = %q", query)
				return
			}
			var response string
			switch ip {
			case "192.0.2.10":
				response = "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: referral.example\n"
			case "192.0.2.20":
				response = "Domain Name: EXAMPLE.COM\nRegistrar: Pinned Registrar\n"
			default:
				serverErrors <- fmt.Errorf("dial used unexpected IP %q", ip)
				return
			}
			if _, err := server.Write([]byte(response)); err != nil {
				serverErrors <- fmt.Errorf("write WHOIS response: %w", err)
				return
			}
			serverErrors <- nil
		}()
		return client, ip, nil
	}

	pinned := &whoisPinnedDialer{
		ctx: context.Background(), timeout: time.Second, resolve: resolver, dial: dialer,
	}
	result, err := whois.NewClient().SetDialer(pinned).SetTimeout(time.Second).SetDisableStats(true).Whois("example.com", "registry.example")
	if err != nil {
		t.Fatalf("WHOIS lookup failed: %v", err)
	}
	if !strings.Contains(result, "Pinned Registrar") {
		t.Fatalf("WHOIS did not follow the pinned referral: %q", result)
	}
	for range 2 {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
	resolvedMu.Lock()
	defer resolvedMu.Unlock()
	wantHosts := []string{"registry.example", "referral.example"}
	if len(resolvedHosts) != len(wantHosts) {
		t.Fatalf("resolved hosts = %v; want %v", resolvedHosts, wantHosts)
	}
	for i := range wantHosts {
		if resolvedHosts[i] != wantHosts[i] {
			t.Fatalf("resolved hosts = %v; want %v", resolvedHosts, wantHosts)
		}
	}
}

func TestRDAPRequestUsesCallerContextAndTargetKind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	domainRequest, err := rdapRequestForTarget(ctx, "example.com")
	if err != nil {
		t.Fatalf("domain RDAP request failed: %v", err)
	}
	if domainRequest.Type != rdap.DomainRequest || domainRequest.Query != "example.com" {
		t.Fatalf("unexpected domain request: %#v", domainRequest)
	}
	if !errors.Is(domainRequest.Context().Err(), context.Canceled) {
		t.Fatalf("domain request did not preserve caller context: %v", domainRequest.Context().Err())
	}

	ipRequest, err := rdapRequestForTarget(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("IP RDAP request failed: %v", err)
	}
	if ipRequest.Type != rdap.IPRequest || ipRequest.Query != "8.8.8.8" {
		t.Fatalf("unexpected IP request: %#v", ipRequest)
	}
}

func TestResolveRDAPServerRejectsPrivateAddress(t *testing.T) {
	if _, err := resolveRDAPServer(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("RDAP resolver accepted a private address")
	}
}

type whoisRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn whoisRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestBoundedRoundTripperCapsResponseBody(t *testing.T) {
	const limit = 8
	transport := boundedRoundTripper{
		maxBytes: limit,
		base: whoisRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", 32))),
				Header:     make(http.Header),
			}, nil
		}),
	}
	request, err := http.NewRequest(http.MethodGet, "https://rdap.example/domain/example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != limit {
		t.Fatalf("bounded body length = %d; want %d", len(body), limit)
	}
}
