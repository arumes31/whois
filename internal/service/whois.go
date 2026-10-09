package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"whois/internal/utils"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"golang.org/x/net/idna"
)

type WhoisInfo struct {
	Raw           string                `json:"raw"`
	Registrar     string                `json:"registrar,omitempty"`
	Expiry        string                `json:"expiry,omitempty"`
	Created       string                `json:"created,omitempty"`
	Kind          string                `json:"kind,omitempty"`
	Source        string                `json:"source,omitempty"`
	SourceURL     string                `json:"source_url,omitempty"`
	QueriedAt     string                `json:"queried_at,omitempty"`
	Domain        string                `json:"domain,omitempty"`
	Handle        string                `json:"handle,omitempty"`
	Statuses      []string              `json:"statuses,omitempty"`
	Nameservers   []string              `json:"nameservers,omitempty"`
	DNSSEC        *RegistrationDNSSEC   `json:"dnssec,omitempty"`
	Network       *RegistrationNetwork  `json:"network,omitempty"`
	Organization  string                `json:"organization,omitempty"`
	AbuseContacts []RegistrationContact `json:"abuse_contacts,omitempty"`
}

// RegistrationDNSSEC contains registry declarations, not DNSSEC validation results.
type RegistrationDNSSEC struct {
	DelegationSigned *bool `json:"delegation_signed,omitempty"`
	ZoneSigned       *bool `json:"zone_signed,omitempty"`
}

type RegistrationNetwork struct {
	Handle       string `json:"handle,omitempty"`
	Name         string `json:"name,omitempty"`
	StartAddress string `json:"start_address"`
	EndAddress   string `json:"end_address"`
	IPVersion    string `json:"ip_version,omitempty"`
	Country      string `json:"country,omitempty"`
	Type         string `json:"type,omitempty"`
}

type RegistrationContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

var errRegistrationNotFound = errors.New("registration record not found")

// WhoisFunc performs WHOIS lookups. The context-aware signature ensures that
// connection setup uses the same caller cancellation and address policy as the
// rest of the request.
var WhoisFunc = func(ctx context.Context, target string, servers ...string) (string, error) {
	dialer := &whoisPinnedDialer{
		ctx:     ctx,
		timeout: 8 * time.Second,
		resolve: resolveWhoisServer,
		dial:    utils.DialResolvedTarget,
	}
	return whois.NewClient().SetDialer(dialer).SetTimeout(8*time.Second).Whois(target, servers...)
}

var WhoisServerValidator = validateWhoisServer

var RdapLookupFunc = rdapLookup

const (
	rdapTimeout          = 15 * time.Second
	maxRDAPResponseBytes = 4 * 1024 * 1024
)

type whoisResult struct {
	raw string
	err error
}

func callWithContext(ctx context.Context, lookup func() (string, error)) (string, error) {
	result := make(chan whoisResult, 1)
	go func() {
		raw, err := lookup()
		result <- whoisResult{raw: raw, err: err}
	}()
	select {
	case response := <-result:
		return response.raw, response.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func callWhois(ctx context.Context, target string, servers ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, server := range servers {
		if err := WhoisServerValidator(ctx, server); err != nil {
			return "", err
		}
	}
	return callWithContext(ctx, func() (string, error) { return WhoisFunc(ctx, target, servers...) })
}

func validateWhoisServer(ctx context.Context, server string) error {
	_, err := resolveWhoisServer(ctx, server)
	return err
}

func resolveWhoisServer(ctx context.Context, server string) ([]net.IPAddr, error) {
	host, err := whoisServerHost(server)
	if err != nil {
		return nil, err
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve WHOIS server: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("WHOIS server resolved to no addresses")
	}
	for _, address := range addresses {
		if !utils.IsPublicIP(address.IP) {
			return nil, fmt.Errorf("WHOIS server resolves to a non-public address")
		}
	}
	return addresses, nil
}

func whoisServerHost(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("WHOIS server is empty")
	}
	if strings.Contains(server, "://") {
		parsed, err := url.Parse(server)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid WHOIS server")
		}
		server = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(server); err == nil {
		server = host
	}
	server = strings.Trim(strings.TrimSuffix(server, "."), "[]")
	if server == "" {
		return "", fmt.Errorf("invalid WHOIS server")
	}
	return server, nil
}

type whoisResolver func(context.Context, string) ([]net.IPAddr, error)
type whoisDial func(context.Context, string, []net.IPAddr, string, time.Duration) (net.Conn, string, error)

// whoisPinnedDialer preserves the hostname passed through the WHOIS protocol
// while connecting only to the numeric addresses validated for that exact dial.
// The library may discover referrals internally, so policy enforcement belongs
// in the dialer and applies to both initial and referred servers.
type whoisPinnedDialer struct {
	ctx     context.Context
	timeout time.Duration
	resolve whoisResolver
	dial    whoisDial
}

func (d *whoisPinnedDialer) Dial(network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid WHOIS address: %w", err)
	}
	addresses, err := d.resolve(d.ctx, host)
	if err != nil {
		return nil, err
	}
	conn, _, err := d.dial(d.ctx, network, addresses, port, d.timeout)
	return conn, err
}

func Whois(ctx context.Context, target string) interface{} {
	if !utils.IsValidTarget(target) {
		return "Error: invalid target for WHOIS"
	}
	if err := ctx.Err(); err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}
	info, rdapErr := RdapLookupFunc(ctx, target)
	if err := ctx.Err(); err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}
	if rdapErr == nil && strings.TrimSpace(info.Raw) != "" {
		return info
	}
	if errors.Is(rdapErr, errRegistrationNotFound) {
		return "WHOIS error: registration record not found in the authoritative RDAP service"
	}

	raw, err := callWhois(ctx, target)
	if ctx.Err() != nil {
		return fmt.Sprintf("WHOIS error: %v", ctx.Err())
	}

	// Determine TLD
	tld := ""
	parts := strings.Split(target, ".")
	if len(parts) > 1 {
		tld = strings.ToLower(parts[len(parts)-1])
	}

	// Expanded fallback map with multiple servers per TLD
	fallbacks := map[string][]string{
		"info":   {"whois.nic.info", "whois.afilias.net", "whois.identity.digital"},
		"biz":    {"whois.nic.biz", "whois.neulevel.biz", "whois.biz"},
		"mobi":   {"whois.dotmobi.net", "whois.afilias.net"},
		"online": {"whois.nic.online", "whois.centralnic.com"},
		"site":   {"whois.nic.site", "whois.centralnic.com"},
		"top":    {"whois.nic.top", "whois.centralnic.com"},
		"xyz":    {"whois.nic.xyz", "whois.centralnic.com", "whois.nic.gmo"},
		"shop":   {"whois.nic.shop", "whois.gmo-registry.com"},
		"cloud":  {"whois.nic.cloud", "whois.centralnic.com"},
		"tech":   {"whois.nic.tech", "whois.centralnic.com"},
		"vip":    {"whois.nic.vip", "whois.centralnic.com"},
		"icu":    {"whois.nic.icu", "whois.centralnic.com"},
		"club":   {"whois.nic.club", "whois.centralnic.com"},
		"me":     {"whois.nic.me", "whois.meregistry.net"},
		"io":     {"whois.nic.io", "whois.io-registry.net"},
		"co":     {"whois.nic.co", "whois.cointernet.co"},
		"tv":     {"whois.nic.tv", "whois.verisign-grs.com"},
		"cc":     {"whois.nic.cc", "whois.verisign-grs.com"},
		"us":     {"whois.nic.us", "whois.neustar.us"},
	}

	isErrorResponse := func(r string) bool {
		rLower := strings.ToLower(r)
		return len(r) < 100 ||
			strings.Contains(rLower, "tld is not supported") ||
			strings.Contains(rLower, "invalid tld") ||
			strings.Contains(rLower, "no whois server found")
	}

	// If primary failed or returned error, try fallbacks
	if err != nil || isErrorResponse(raw) {
		if servers, ok := fallbacks[tld]; ok {
			shuffled := make([]string, len(servers))
			copy(shuffled, servers)
			for i := len(shuffled) - 1; i > 0; i-- {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
				if err != nil {
					continue
				}
				j := int(n.Int64())
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			}

			for _, s := range shuffled {
				rRaw, rErr := callWhois(ctx, target, s)
				if rErr == nil && !isErrorResponse(rRaw) {
					raw = rRaw
					err = nil
					break
				}
			}
		}

		// Still no good result? Try recursive IANA lookup
		if err != nil || isErrorResponse(raw) {
			ianaRaw, ianaErr := callWhois(ctx, target, "whois.iana.org")
			if ianaErr == nil {
				lines := strings.Split(ianaRaw, "\n")
				for _, line := range lines {
					lowerLine := strings.ToLower(strings.TrimSpace(line))
					if strings.HasPrefix(lowerLine, "whois:") || strings.HasPrefix(lowerLine, "refer:") {
						rParts := strings.Split(line, ":")
						if len(rParts) > 1 {
							server := strings.TrimSpace(rParts[1])
							if server != "" {
								ianaResultRaw, ianaResultErr := callWhois(ctx, target, server)
								if ianaResultErr == nil && !isErrorResponse(ianaResultRaw) {
									raw = ianaResultRaw
									err = nil
									break
								}
							}
						}
					}
				}
			}
		}

	}

	if ctx.Err() != nil {
		return fmt.Sprintf("WHOIS error: %v", ctx.Err())
	}
	if err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}
	if isErrorResponse(raw) {
		return "WHOIS error: no usable registration data returned by RDAP or WHOIS"
	}

	// Follow registrar referral if present in registry output
	if strings.Contains(raw, "Registrar WHOIS Server:") {
		lines := strings.Split(raw, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Registrar WHOIS Server:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					refServer := strings.TrimSpace(parts[1])
					if refServer != "" {
						refRaw, refErr := callWhois(ctx, target, refServer)
						if refErr == nil && len(refRaw) > len(raw)/2 {
							raw = refRaw
						}
						break
					}
				}
			}
		}
	}

	if ctx.Err() != nil {
		return fmt.Sprintf("WHOIS error: %v", ctx.Err())
	}
	// Filter raw lines - only skip if the line STARTS with % or # (comments)
	lines := strings.Split(raw, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "" && (len(filtered) == 0 || filtered[len(filtered)-1] == "") {
			continue
		}
		filtered = append(filtered, line)
	}
	raw = strings.Join(filtered, "\n")
	if strings.TrimSpace(raw) == "" {
		return "WHOIS error: no usable registration data returned by WHOIS"
	}
	info = WhoisInfo{Raw: raw, Source: "whois", QueriedAt: time.Now().UTC().Format(time.RFC3339), Kind: "domain"}
	if net.ParseIP(target) != nil {
		info.Kind = "ip"
		return info
	}

	result, err := whoisparser.Parse(raw)
	if err != nil {
		if errors.Is(err, whoisparser.ErrNotFoundDomain) || errors.Is(err, whoisparser.ErrDomainLimitExceed) {
			return fmt.Sprintf("WHOIS error: %v", err)
		}
		return info
	}

	if result.Registrar != nil {
		info.Registrar = result.Registrar.Name
	}
	if result.Domain != nil {
		info.Expiry = result.Domain.ExpirationDate
		info.Created = result.Domain.CreatedDate
		info.Domain = result.Domain.Domain
		info.Handle = result.Domain.ID
		info.Statuses = result.Domain.Status
		info.Nameservers = result.Domain.NameServers
	}
	if result.Registrant != nil {
		info.Organization = result.Registrant.Organization
	}

	return info
}

func rdapLookup(ctx context.Context, target string) (WhoisInfo, error) {
	request, err := rdapRequestForTarget(ctx, target)
	if err != nil {
		return WhoisInfo{}, err
	}
	httpClient := safeRDAPHTTPClient()
	defer httpClient.CloseIdleConnections()
	client := &rdap.Client{HTTP: httpClient, Bootstrap: &bootstrap.Client{HTTP: httpClient}}
	response, err := client.Do(request)
	if err != nil {
		var clientErr *rdap.ClientError
		if errors.As(err, &clientErr) && clientErr.Type == rdap.ObjectDoesNotExist {
			return WhoisInfo{}, errRegistrationNotFound
		}
		return WhoisInfo{}, err
	}
	return registrationFromRDAP(response, request.Query)
}

func registrationFromRDAP(response *rdap.Response, target string) (WhoisInfo, error) {
	if response == nil {
		return WhoisInfo{}, errors.New("empty RDAP response")
	}
	info := WhoisInfo{Source: "rdap", QueriedAt: time.Now().UTC().Format(time.RFC3339)}
	var entities []rdap.Entity
	var events []rdap.Event
	switch object := response.Object.(type) {
	case *rdap.Domain:
		if object == nil || (object.LDHName == "" && object.UnicodeName == "" && object.Handle == "") {
			return WhoisInfo{}, errors.New("RDAP response contains no domain registration data")
		}
		if net.ParseIP(target) != nil {
			return WhoisInfo{}, errors.New("RDAP returned a domain for an IP lookup")
		}
		info.Kind, info.Domain, info.Handle = "domain", object.LDHName, object.Handle
		if info.Domain == "" {
			info.Domain = object.UnicodeName
		}
		requestedName, requestedErr := idna.Lookup.ToASCII(strings.TrimSuffix(target, "."))
		returnedName, returnedErr := idna.Lookup.ToASCII(strings.TrimSuffix(info.Domain, "."))
		if requestedErr != nil || returnedErr != nil || returnedName == "" || !strings.EqualFold(requestedName, returnedName) {
			return WhoisInfo{}, errors.New("RDAP response does not match the requested domain")
		}
		info.Statuses = slices.Clone(object.Status)
		for _, ns := range object.Nameservers {
			name := ns.LDHName
			if name == "" {
				name = ns.UnicodeName
			}
			if name != "" {
				info.Nameservers = append(info.Nameservers, name)
			}
		}
		if secure := object.SecureDNS; secure != nil && (secure.DelegationSigned != nil || secure.ZoneSigned != nil) {
			info.DNSSEC = &RegistrationDNSSEC{DelegationSigned: secure.DelegationSigned, ZoneSigned: secure.ZoneSigned}
		}
		entities, events = object.Entities, object.Events
	case *rdap.IPNetwork:
		if object == nil {
			return WhoisInfo{}, errors.New("empty RDAP IP network")
		}
		start, startErr := netip.ParseAddr(object.StartAddress)
		end, endErr := netip.ParseAddr(object.EndAddress)
		ip, ipErr := netip.ParseAddr(target)
		start, end, ip = start.Unmap(), end.Unmap(), ip.Unmap()
		if startErr != nil || endErr != nil || ipErr != nil || start.BitLen() != end.BitLen() ||
			start.Compare(end) > 0 || ip.BitLen() != start.BitLen() || ip.Compare(start) < 0 || ip.Compare(end) > 0 {
			return WhoisInfo{}, errors.New("RDAP response contains no matching IP network range")
		}
		info.Kind, info.Handle = "ip", object.Handle
		info.Statuses = slices.Clone(object.Status)
		info.Network = &RegistrationNetwork{
			Handle: object.Handle, Name: object.Name, StartAddress: start.String(), EndAddress: end.String(),
			IPVersion: object.IPVersion, Country: object.Country, Type: object.Type,
		}
		entities, events = object.Entities, object.Events
	case *rdap.Error:
		if object != nil && object.ErrorCode != nil && *object.ErrorCode == http.StatusNotFound {
			return WhoisInfo{}, errRegistrationNotFound
		}
		return WhoisInfo{}, errors.New("RDAP server returned an error response")
	default:
		return WhoisInfo{}, errors.New("RDAP response contains no supported registration object")
	}
	for _, event := range events {
		switch event.Action {
		case "registration":
			info.Created = event.Date
		case "expiration":
			info.Expiry = event.Date
		}
	}
	collectRegistrationEntities(&info, entities)
	// Preserve the original JSON, including notices and redaction metadata, rather
	// than flattening IP responses through the library's domain-only converter.
	for i := len(response.HTTP) - 1; i >= 0; i-- {
		h := response.HTTP[i]
		if h == nil || h.Error != nil || !json.Valid(h.Body) {
			continue
		}
		info.Raw = string(h.Body)
		sourceURL := h.URL
		if h.Response != nil && h.Response.Request != nil && h.Response.Request.URL != nil {
			sourceURL = h.Response.Request.URL.String()
		}
		info.SourceURL = registrationSourceURL(sourceURL)
		break
	}
	if info.Raw == "" {
		data, err := json.MarshalIndent(response.Object, "", "  ")
		if err != nil {
			return WhoisInfo{}, fmt.Errorf("render RDAP evidence: %w", err)
		}
		info.Raw = string(data)
	}
	return info, nil
}

func registrationSourceURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return ""
	}
	return u.String()
}

func collectRegistrationEntities(info *WhoisInfo, entities []rdap.Entity) {
	// Roles apply to the containing object. Nested registrants belong to their
	// parent entity, not to the domain/network whose ownership we are displaying.
	for _, entity := range entities {
		name, organization := registrationEntityNames(entity)
		if slices.Contains(entity.Roles, "registrar") && info.Registrar == "" {
			info.Registrar = name
		}
		if slices.Contains(entity.Roles, "registrant") && info.Organization == "" {
			info.Organization = organization
			if info.Organization == "" {
				info.Organization = name
			}
		}
	}
	pending := slices.Clone(entities)
	for len(pending) > 0 {
		entity := pending[len(pending)-1]
		pending = append(pending[:len(pending)-1], entity.Entities...)
		if entity.VCard == nil || !slices.Contains(entity.Roles, "abuse") {
			continue
		}
		name, _ := registrationEntityNames(entity)
		emails := registrationVCardValues(entity.VCard, "email")
		phones := registrationVCardValues(entity.VCard, "tel")
		for i := range max(1, len(emails), len(phones)) {
			contact := RegistrationContact{Name: name}
			if i < len(emails) {
				contact.Email = emails[i]
			}
			if i < len(phones) {
				contact.Phone = phones[i]
			}
			if contact != (RegistrationContact{}) && !slices.Contains(info.AbuseContacts, contact) {
				info.AbuseContacts = append(info.AbuseContacts, contact)
			}
		}
	}
}

func registrationEntityNames(entity rdap.Entity) (string, string) {
	if entity.VCard == nil {
		return "", ""
	}
	name := strings.Join(registrationVCardValues(entity.VCard, "fn"), "; ")
	organization := strings.Join(registrationVCardValues(entity.VCard, "org"), "; ")
	if name == "" {
		name = organization
	}
	return name, organization
}

func registrationVCardValues(card *rdap.VCard, field string) []string {
	var values []string
	for _, property := range card.Properties {
		if property == nil || property.Name != field {
			continue
		}
		for _, value := range property.Values() {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func rdapRequestForTarget(ctx context.Context, target string) (*rdap.Request, error) {
	info := utils.NormalizeTarget(target)
	if !info.Valid || !info.Networkable {
		return nil, fmt.Errorf("invalid RDAP target")
	}
	var request *rdap.Request
	if ip := net.ParseIP(info.Host); ip != nil {
		request = rdap.NewIPRequest(ip)
	} else {
		request = rdap.NewDomainRequest(info.Host)
	}
	request.Timeout = rdapTimeout
	return request.WithContext(ctx), nil
}

func safeRDAPHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := resolveRDAPServer(ctx, host)
			if err != nil {
				return nil, err
			}
			conn, _, err := utils.DialResolvedTarget(ctx, network, addresses, port, rdapTimeout)
			return conn, err
		},
	}
	return &http.Client{
		Timeout:   rdapTimeout,
		Transport: boundedRoundTripper{base: transport, maxBytes: maxRDAPResponseBytes},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 RDAP redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("RDAP redirect uses unsupported scheme")
			}
			if _, err := resolveRDAPServer(req.Context(), req.URL.Hostname()); err != nil {
				return fmt.Errorf("unsafe RDAP redirect: %w", err)
			}
			return nil
		},
	}
}

func resolveRDAPServer(ctx context.Context, host string) ([]net.IPAddr, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve RDAP server: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("RDAP server resolved to no addresses")
	}
	for _, address := range addresses {
		if !utils.IsPublicIP(address.IP) {
			return nil, fmt.Errorf("RDAP server resolves to a non-public address")
		}
	}
	return addresses, nil
}

type boundedRoundTripper struct {
	base     http.RoundTripper
	maxBytes int64
}

func (t boundedRoundTripper) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t boundedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = &boundedReadCloser{Reader: io.LimitReader(response.Body, t.maxBytes), Closer: response.Body}
	return response, nil
}

type boundedReadCloser struct {
	io.Reader
	io.Closer
}
