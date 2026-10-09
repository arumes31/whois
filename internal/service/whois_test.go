package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
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

func TestWhoisPrefersRDAP(t *testing.T) {
	oldWhois, oldRDAP := WhoisFunc, RdapLookupFunc
	t.Cleanup(func() { WhoisFunc, RdapLookupFunc = oldWhois, oldRDAP })
	whoisCalls := 0
	WhoisFunc = func(context.Context, string, ...string) (string, error) {
		whoisCalls++
		return strings.Repeat("Legacy response ", 10) + "\nDomain Name: EXAMPLE.COM", nil
	}
	RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
		return WhoisInfo{Raw: "Domain Name: EXAMPLE.COM\nRegistrar: RDAP Registrar", Source: "rdap"}, nil
	}
	result := Whois(context.Background(), "example.com")
	info, ok := result.(WhoisInfo)
	if !ok || !strings.Contains(info.Raw, "RDAP Registrar") || whoisCalls != 0 {
		t.Fatalf("RDAP-first lookup = %#v; WHOIS calls = %d", result, whoisCalls)
	}
}

func TestRDAPIPNetworkRetainsRawEvidence(t *testing.T) {
	response := &rdap.Response{Object: &rdap.IPNetwork{
		Handle: "NET-1-1-1-0-1", Name: "CLOUDFLARENET",
		StartAddress: "1.1.1.0", EndAddress: "1.1.1.255", IPVersion: "v4",
	}}
	info, err := registrationFromRDAP(response, "::ffff:1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	raw := info.Raw
	for _, want := range []string{"NET-1-1-1-0-1", "CLOUDFLARENET", "1.1.1.0", "1.1.1.255"} {
		if !strings.Contains(raw, want) {
			t.Errorf("IP registration evidence missing %q: %q", want, raw)
		}
	}
}

func TestRDAPRegistrationDomainFields(t *testing.T) {
	raw := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","handle":"DOMAIN-1","status":["client transfer prohibited"],"nameservers":[{"ldhName":"NS1.EXAMPLE.COM"}],"secureDNS":{"delegationSigned":false},"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"}],"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]]},{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Holder Name"],["org",{},"text","Example Holder"]]],"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.com"],["email",{},"text","security@example.com"],["tel",{},"uri","tel:+1-555-0100"]]]}]}],"notices":[{"title":"Privacy","description":["Some contact data is redacted"]}]}`
	object, err := rdap.NewDecoder([]byte(raw)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	finalURL, err := url.Parse("https://registry.example/rdap/domain/example.com")
	if err != nil {
		t.Fatal(err)
	}
	info, err := registrationFromRDAP(&rdap.Response{Object: object, HTTP: []*rdap.HTTPResponse{{
		URL: "https://bootstrap.example/domain/example.com", Body: []byte(raw),
		Response: &http.Response{Request: &http.Request{URL: finalURL}},
	}}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "domain" || info.Domain != "EXAMPLE.COM" || info.Handle != "DOMAIN-1" || info.Source != "rdap" ||
		info.SourceURL != finalURL.String() || info.Raw != raw || info.Registrar != "Example Registrar" || info.Organization != "Example Holder" {
		t.Fatalf("domain registration fields lost: %#v", info)
	}
	if info.Created != "1995-08-14T04:00:00Z" || info.Expiry != "2027-08-13T04:00:00Z" ||
		!slices.Equal(info.Statuses, []string{"client transfer prohibited"}) || !slices.Equal(info.Nameservers, []string{"NS1.EXAMPLE.COM"}) {
		t.Fatalf("domain dates/status/nameservers lost: %#v", info)
	}
	if info.DNSSEC == nil || info.DNSSEC.DelegationSigned == nil || *info.DNSSEC.DelegationSigned || info.DNSSEC.ZoneSigned != nil {
		t.Fatalf("DNSSEC false and unknown must remain distinct: %#v", info.DNSSEC)
	}
	if len(info.AbuseContacts) != 2 || info.AbuseContacts[0].Email != "abuse@example.com" ||
		info.AbuseContacts[0].Phone != "tel:+1-555-0100" || info.AbuseContacts[1].Email != "security@example.com" {
		t.Fatalf("nested abuse contacts lost: %#v", info.AbuseContacts)
	}
	if _, err := time.Parse(time.RFC3339, info.QueriedAt); err != nil {
		t.Fatalf("lookup timestamp: %v", err)
	}
}

func TestRDAPRegistrationIPFields(t *testing.T) {
	raw := `{"objectClassName":"ip network","handle":"NET6-GOOGLE","name":"GOOGLE-IPV6","startAddress":"2001:4860::","endAddress":"2001:4860:ffff:ffff:ffff:ffff:ffff:ffff","ipVersion":"v6","country":"US","type":"DIRECT ALLOCATION","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google LLC"]]]}]}`
	object, err := rdap.NewDecoder([]byte(raw)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	info, err := registrationFromRDAP(&rdap.Response{Object: object, HTTP: []*rdap.HTTPResponse{{
		URL: "https://rdap.arin.net/registry/ip/2001:4860:4860::8888", Body: []byte(raw),
	}}}, "2001:4860:4860::8888")
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "ip" || info.Network == nil || info.Network.Handle != "NET6-GOOGLE" ||
		info.Network.Name != "GOOGLE-IPV6" || info.Network.Country != "US" || info.Network.IPVersion != "v6" ||
		info.Network.Type != "DIRECT ALLOCATION" || info.Organization != "Google LLC" || info.Registrar != "" || info.Raw != raw {
		t.Fatalf("IP registration fields lost: %#v", info)
	}
}

func TestRDAPHolderUsesRootEntityRoles(t *testing.T) {
	card := func(name string) *rdap.VCard {
		return &rdap.VCard{Properties: []*rdap.VCardProperty{{Name: "fn", Value: name}}}
	}
	info, err := registrationFromRDAP(&rdap.Response{Object: &rdap.Domain{
		LDHName: "example.com", Entities: []rdap.Entity{
			{Roles: []string{"registrant"}, VCard: card("Domain Holder")},
			{Roles: []string{"registrar"}, VCard: card("Domain Registrar"), Entities: []rdap.Entity{
				{Roles: []string{"registrant"}, VCard: card("Registrar Holder")},
				{Roles: []string{"registrar"}, VCard: card("Unrelated Registrar")},
			}},
		},
	}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if info.Organization != "Domain Holder" || info.Registrar != "Domain Registrar" {
		t.Fatalf("nested entity roles replaced domain ownership: %#v", info)
	}
}

func TestRDAPDomainIdentityAcceptsCaseTrailingDotAndIDN(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"EXAMPLE.COM", "example.com."},
		{"xn--bcher-kva.example", "bücher.example"},
	} {
		_, err := registrationFromRDAP(&rdap.Response{Object: &rdap.Domain{LDHName: tc.name}}, tc.target)
		if err != nil {
			t.Errorf("matching domain %q / %q rejected: %v", tc.name, tc.target, err)
		}
	}
}

func TestRDAPRejectsEmptyErrorAndMismatchedObjects(t *testing.T) {
	notFound := uint16(404)
	for _, tc := range []struct {
		name   string
		object rdap.RDAPObject
		target string
	}{
		{"nil object", nil, "example.com"},
		{"nil domain", (*rdap.Domain)(nil), "example.com"},
		{"empty domain", &rdap.Domain{}, "example.com"},
		{"unrelated domain", &rdap.Domain{LDHName: "different.com"}, "example.com"},
		{"handle without matching domain", &rdap.Domain{Handle: "DOMAIN-1"}, "example.com"},
		{"empty network", &rdap.IPNetwork{}, "1.1.1.1"},
		{"wrong object", &rdap.Domain{LDHName: "example.com"}, "1.1.1.1"},
		{"unrelated range", &rdap.IPNetwork{StartAddress: "8.8.8.0", EndAddress: "8.8.8.255"}, "1.1.1.1"},
		{"reversed range", &rdap.IPNetwork{StartAddress: "1.1.1.255", EndAddress: "1.1.1.0"}, "1.1.1.1"},
		{"not found", &rdap.Error{ErrorCode: &notFound}, "example.com"},
		{"error object", &rdap.Error{Title: "Server failure"}, "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := registrationFromRDAP(&rdap.Response{Object: tc.object}, tc.target)
			if err == nil || info.Raw != "" {
				t.Fatalf("invalid response became a successful result: %#v, %v", info, err)
			}
			if tc.name == "not found" && !errors.Is(err, errRegistrationNotFound) {
				t.Fatalf("authoritative not found lost: %v", err)
			}
		})
	}
}

func TestRegistrationSourceURLRejectsUnsafeSchemes(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "data:text/html,evil", "//registry.example/path", "https://user:secret@registry.example/", "https:///missing-host", "https://registry.example/\n"} {
		if got := registrationSourceURL(raw); got != "" {
			t.Errorf("unsafe source URL retained: %q", got)
		}
	}
	const safe = "https://registry.example/domain/example.com"
	if got := registrationSourceURL(safe); got != safe {
		t.Errorf("source URL = %q, want %q", got, safe)
	}
}

func TestWhoisRDAPFallbackAndCancellation(t *testing.T) {
	oldWhois, oldRDAP, oldValidator := WhoisFunc, RdapLookupFunc, WhoisServerValidator
	t.Cleanup(func() { WhoisFunc, RdapLookupFunc, WhoisServerValidator = oldWhois, oldRDAP, oldValidator })
	WhoisServerValidator = func(context.Context, string) error { return nil }
	for _, tc := range []struct {
		name         string
		rdapErr      error
		cancelBefore bool
		cancelDuring bool
		wantWhois    bool
	}{
		{name: "unsupported falls back", rdapErr: &rdap.ClientError{Type: rdap.BootstrapNotSupported}, wantWhois: true},
		{name: "empty response falls back", wantWhois: true},
		{name: "authoritative not found", rdapErr: errRegistrationNotFound},
		{name: "already canceled", cancelBefore: true},
		{name: "canceled during RDAP", cancelDuring: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []string
			if tc.cancelBefore {
				cancel()
			}
			RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
				calls = append(calls, "rdap")
				if tc.cancelDuring {
					cancel()
				}
				return WhoisInfo{}, tc.rdapErr
			}
			WhoisFunc = func(context.Context, string, ...string) (string, error) {
				calls = append(calls, "whois")
				return "Domain Name: EXAMPLE.COM\nRegistrar: Legacy Registrar\nCreation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2027-08-13T04:00:00Z", nil
			}
			result := Whois(ctx, "example.com")
			if tc.wantWhois {
				info, ok := result.(WhoisInfo)
				if !ok || info.Source != "whois" || info.Registrar != "Legacy Registrar" || !slices.Equal(calls, []string{"rdap", "whois"}) {
					t.Fatalf("WHOIS fallback = %#v, calls %v", result, calls)
				}
			} else {
				message, ok := result.(string)
				if !ok || !strings.HasPrefix(message, "WHOIS error:") || slices.Contains(calls, "whois") || (tc.cancelBefore && len(calls) != 0) {
					t.Fatalf("lookup should stop, got %#v, calls %v", result, calls)
				}
			}
		})
	}
}

func TestWhoisDoesNotReportEmptyOrMissingRegistrationAsSuccess(t *testing.T) {
	oldWhois, oldRDAP, oldValidator := WhoisFunc, RdapLookupFunc, WhoisServerValidator
	t.Cleanup(func() { WhoisFunc, RdapLookupFunc, WhoisServerValidator = oldWhois, oldRDAP, oldValidator })
	WhoisServerValidator = func(context.Context, string) error { return nil }
	RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
		return WhoisInfo{}, errors.New("RDAP unavailable")
	}
	for _, raw := range []string{"", "No whois server found", strings.Repeat("% Registry disclaimer\n", 8),
		"No match for EXAMPLE.COM\n" + strings.Repeat("Registry disclaimer. ", 8)} {
		WhoisFunc = func(context.Context, string, ...string) (string, error) { return raw, nil }
		result := Whois(context.Background(), "example.com")
		message, ok := result.(string)
		if !ok || !strings.HasPrefix(message, "WHOIS error:") {
			t.Errorf("empty/not-found response became success: %#v", result)
		}
	}
}

func TestWhois(t *testing.T) {
	oldWhois := WhoisFunc
	oldRDAP := RdapLookupFunc
	oldValidator := WhoisServerValidator
	defer func() {
		WhoisFunc = oldWhois
		RdapLookupFunc = oldRDAP
		WhoisServerValidator = oldValidator
	}()
	WhoisServerValidator = func(context.Context, string) error { return nil }
	RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
		return WhoisInfo{}, errors.New("RDAP unsupported")
	}

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
	RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
		return WhoisInfo{}, errors.New("RDAP unsupported")
	}

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

	t.Run("RDAP success avoids unavailable IANA", func(t *testing.T) {
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
		RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
			return WhoisInfo{Raw: "Mock RDAP Data for IANA Failure"}, nil
		}

		res := Whois(context.Background(), "test.com")
		info, ok := res.(WhoisInfo)
		if !ok || info.Raw != "Mock RDAP Data for IANA Failure" {
			t.Errorf("Expected RDAP fallback on IANA failure, got %v", res)
		}
	})

	t.Run("RDAP success avoids unavailable referral", func(t *testing.T) {
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
		RdapLookupFunc = func(context.Context, string) (WhoisInfo, error) {
			return WhoisInfo{Raw: "Mock RDAP Data for Referral Failure"}, nil
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

type idleClosingWhoisTransport struct {
	closed bool
}

func (t *idleClosingWhoisTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused test transport")
}

func (t *idleClosingWhoisTransport) CloseIdleConnections() { t.closed = true }

func TestRDAPClientClosesUnderlyingIdleConnections(t *testing.T) {
	base := &idleClosingWhoisTransport{}
	client := &http.Client{Transport: boundedRoundTripper{base: base, maxBytes: 8}}
	client.CloseIdleConnections()
	if !base.closed {
		t.Fatal("closing the RDAP client left its underlying connections open")
	}
}

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
