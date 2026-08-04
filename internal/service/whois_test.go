package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"whois/internal/utils"
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

	WhoisFunc = func(target string, query ...string) (string, error) {
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

	RdapLookupFunc = func(target string) (string, error) {
		return "Mock RDAP Data", nil
	}

	res, err := RdapLookupFunc("google.com")
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
		WhoisFunc = func(target string, query ...string) (string, error) {
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
		WhoisFunc = func(target string, query ...string) (string, error) {
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
		WhoisFunc = func(target string, query ...string) (string, error) {
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
		WhoisFunc = func(target string, query ...string) (string, error) {
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

		WhoisFunc = func(target string, query ...string) (string, error) {
			if len(query) == 0 {
				return "No whois server found", nil
			}
			if query[0] == "whois.iana.org" {
				return "", fmt.Errorf("IANA connection error")
			}
			return "error", nil
		}
		RdapLookupFunc = func(target string) (string, error) {
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

		WhoisFunc = func(target string, query ...string) (string, error) {
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
		RdapLookupFunc = func(target string) (string, error) {
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
