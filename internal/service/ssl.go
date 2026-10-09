package service

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- OCSP ResponderID key hashes are SHA-1 by RFC 6960.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"whois/internal/model"
	"whois/internal/utils"
)

const tlsTimeout = 5 * time.Second

func GetSSLInfo(ctx context.Context, target string) *model.SSLInfo {
	targetInfo := utils.NormalizeTarget(target)
	if !targetInfo.Valid || !targetInfo.Networkable {
		return &model.SSLInfo{Error: "invalid target host"}
	}
	host, port := targetInfo.Host, targetInfo.Port
	if port == "" {
		port = "443"
	}

	conn, verified, verificationErr, err := openTLS(ctx, host, port, false, 0, 0)
	if err != nil {
		conn, _, _, err = openTLS(ctx, host, port, true, 0, 0)
		verified = false
	}
	if err != nil {
		return &model.SSLInfo{Error: err.Error(), VerificationError: verificationErr}
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &model.SSLInfo{Error: "no certificates found"}
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	hostnameErr := leaf.VerifyHostname(host)
	selfSigned := leaf.CheckSignatureFrom(leaf) == nil && leaf.RawIssuer != nil && string(leaf.RawIssuer) == string(leaf.RawSubject)

	info := &model.SSLInfo{
		Issuer: leaf.Issuer.String(), Subject: leaf.Subject.String(), Expiry: leaf.NotAfter.Format(time.RFC3339),
		DaysLeft: daysLeft, Protocol: tlsVersionName(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Verified: verified, HostnameValid: hostnameErr == nil, SelfSigned: selfSigned, Expired: now.After(leaf.NotAfter),
		ExpiringSoon: daysLeft >= 0 && daysLeft < 30, SANs: append([]string(nil), leaf.DNSNames...),
		IPSANs:            certificateIPs(leaf),
		FingerprintSHA256: certificateFingerprint(leaf), ALPN: state.NegotiatedProtocol,
		OCSPStapled: len(state.OCSPResponse) > 0, SCTCount: len(state.SignedCertificateTimestamps),
		VerificationError: verificationErr,
	}
	for _, cert := range state.PeerCertificates {
		info.Chain = append(info.Chain, certificateInfo(cert))
		info.PEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	if info.OCSPStapled {
		inspectOCSP(info, state.OCSPResponse, state.PeerCertificates, now)
	} else {
		info.OCSPStatus = "not stapled"
	}
	info.SupportedVersions = probeTLSVersions(ctx, host, port)
	info.Score, info.Grade, info.Issues = scoreTLS(info, leaf, state.CipherSuite)
	return info
}

func openTLS(ctx context.Context, host, port string, insecure bool, minVersion, maxVersion uint16) (*tls.Conn, bool, string, error) {
	rawConn, _, err := utils.DialTarget(ctx, "tcp", host, port, tlsTimeout)
	if err != nil {
		return nil, false, "", err
	}
	conf := &tls.Config{
		// #nosec G402 -- the fallback intentionally inspects untrusted endpoints and reports Verified=false.
		ServerName: host, InsecureSkipVerify: insecure, MinVersion: minVersion, MaxVersion: maxVersion,
		NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, conf)
	handshakeCtx, cancel := context.WithTimeout(ctx, tlsTimeout)
	defer cancel()
	_ = rawConn.SetDeadline(time.Now().Add(tlsTimeout))
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		_ = rawConn.Close()
		return nil, false, err.Error(), fmt.Errorf("tls handshake: %w", err)
	}
	_ = rawConn.SetDeadline(time.Time{})
	return conn, !insecure, "", nil
}

func certificateInfo(cert *x509.Certificate) model.CertificateInfo {
	return model.CertificateInfo{
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SerialNumber: cert.SerialNumber.String(),
		NotBefore: cert.NotBefore.Format(time.RFC3339), NotAfter: cert.NotAfter.Format(time.RFC3339),
		DNSNames: append([]string(nil), cert.DNSNames...), FingerprintSHA256: certificateFingerprint(cert),
		IPAddresses:        certificateIPs(cert),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String(), IsCA: cert.IsCA,
	}
}

func certificateIPs(cert *x509.Certificate) []string {
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return ips
}

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

func inspectOCSP(info *model.SSLInfo, raw []byte, chain []*x509.Certificate, now time.Time) {
	info.OCSPFreshness = "unknown"
	if len(chain) < 2 {
		info.OCSPStatus = "stapled (issuer unavailable)"
		info.OCSPVerificationError = "the certificate issuer was not supplied by the server"
		return
	}
	leaf, issuer := chain[0], chain[1]
	response, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil {
		info.OCSPStatus = "stapled (unparseable)"
		info.OCSPVerificationError = "the OCSP response could not be parsed or its signature is invalid"
		return
	}
	switch response.Status {
	case ocsp.Good:
		info.OCSPStatus = "good"
	case ocsp.Revoked:
		info.OCSPStatus = "revoked"
	case ocsp.Unknown:
		info.OCSPStatus = "unknown"
	default:
		info.OCSPStatus = "server failure"
	}
	if !response.ThisUpdate.IsZero() {
		info.OCSPThisUpdate = response.ThisUpdate.Format(time.RFC3339)
	}
	if !response.NextUpdate.IsZero() {
		info.OCSPNextUpdate = response.NextUpdate.Format(time.RFC3339)
	}
	// RFC 6960 sections 3.2 and 4.2.2.1 require a reliable validity interval.
	// An omitted nextUpdate does not supply an expiry; do not invent one.
	switch {
	case response.ThisUpdate.IsZero(), !response.NextUpdate.IsZero() && response.NextUpdate.Before(response.ThisUpdate):
		info.OCSPFreshness = "invalid"
	case response.ThisUpdate.After(now):
		info.OCSPFreshness = "future"
	case !response.NextUpdate.IsZero() && !response.NextUpdate.After(now):
		info.OCSPFreshness = "stale"
	case !response.NextUpdate.IsZero():
		info.OCSPFreshness = "current"
	}
	if err := authorizeOCSPSigner(response, leaf, issuer, now); err != nil {
		info.OCSPVerificationError = err.Error()
		return
	}
	info.OCSPVerified = true
}

func authorizeOCSPSigner(response *ocsp.Response, leaf, issuer *x509.Certificate, now time.Time) error {
	if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || leaf.CheckSignatureFrom(issuer) != nil {
		return fmt.Errorf("the supplied OCSP issuer did not issue the target certificate")
	}
	signer := issuer
	if response.Certificate != nil && !bytes.Equal(response.Certificate.Raw, issuer.Raw) {
		signer = response.Certificate
		// ParseResponseForCert verifies signatures, but delegated authorization
		// and certificate validity still need RFC 6960 section 4.2.2.2 checks.
		if !bytes.Equal(signer.RawIssuer, issuer.RawSubject) || signer.CheckSignatureFrom(issuer) != nil {
			return fmt.Errorf("the OCSP signer was not issued directly by the certificate issuer")
		}
		if !slices.Contains(signer.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
			return fmt.Errorf("the delegated signer certificate does not permit OCSP signing")
		}
		roots := x509.NewCertPool()
		roots.AddCert(issuer)
		if _, err := signer.Verify(x509.VerifyOptions{
			Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		}); err != nil {
			return fmt.Errorf("delegated OCSP signer authorization failed: %w", err)
		}
		// RFC 5280 section 4.2.1.12 permits digitalSignature and/or
		// contentCommitment (nonRepudiation) for delegated OCSP signing.
		if signer.KeyUsage != 0 && signer.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
			return fmt.Errorf("the delegated OCSP signer certificate does not permit signing responses")
		}
	}
	if now.Before(signer.NotBefore) || now.After(signer.NotAfter) {
		return fmt.Errorf("the OCSP signer certificate is outside its validity period")
	}
	if !ocspResponderMatches(response, signer) {
		return fmt.Errorf("the OCSP responder identity does not match the signing certificate")
	}
	return nil
}

func ocspResponderMatches(response *ocsp.Response, signer *x509.Certificate) bool {
	if len(response.RawResponderName) > 0 {
		return bytes.Equal(response.RawResponderName, signer.RawSubject)
	}
	var publicKeyInfo struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return false
	}
	// RFC 6960 section 4.2.1 defines KeyHash as SHA-1 of subjectPublicKey,
	// excluding its tag, length and unused-bit count.
	keyHash := sha1.Sum(publicKeyInfo.PublicKey.RightAlign()) // #nosec G401 -- protocol-defined identity hash, not a signature.
	return bytes.Equal(response.ResponderKeyHash, keyHash[:])
}

func probeTLSVersions(ctx context.Context, host, port string) []string {
	versions := []struct {
		value uint16
		name  string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	supported := make([]string, 0, len(versions))
	for _, version := range versions {
		version := version
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			conn, _, _, err := openTLS(probeCtx, host, port, true, version.value, version.value)
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				supported = append(supported, version.name)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	ordered := make([]string, 0, len(supported))
	for _, version := range versions {
		for _, name := range supported {
			if name == version.name {
				ordered = append(ordered, name)
			}
		}
	}
	return ordered
}

func scoreTLS(info *model.SSLInfo, leaf *x509.Certificate, cipherSuite uint16) (int, string, []string) {
	score := 100
	issues := make([]string, 0)
	addIssue := func(points int, issue string) {
		score -= points
		issues = append(issues, issue)
	}
	if !info.Verified {
		addIssue(35, "certificate chain is not trusted")
	}
	if !info.HostnameValid {
		addIssue(25, "certificate does not match the target hostname")
	}
	if info.Expired {
		addIssue(50, "certificate has expired")
	} else if info.ExpiringSoon {
		addIssue(10, "certificate expires in fewer than 30 days")
	}
	if info.SelfSigned {
		addIssue(15, "leaf certificate is self-signed")
	}
	for _, version := range info.SupportedVersions {
		if version == "TLS 1.0" || version == "TLS 1.1" {
			addIssue(15, version+" is deprecated")
		}
	}
	if suite := tls.CipherSuiteName(cipherSuite); strings.Contains(suite, "3DES") || strings.Contains(suite, "RC4") {
		addIssue(20, "negotiated cipher suite is weak")
	}
	if leaf.SignatureAlgorithm == x509.MD5WithRSA || leaf.SignatureAlgorithm == x509.SHA1WithRSA {
		addIssue(20, "certificate uses a weak signature algorithm")
	}
	if !info.OCSPStapled && len(leaf.OCSPServer) > 0 {
		addIssue(3, "OCSP response is not stapled")
	}
	if info.OCSPStapled && !info.OCSPVerified {
		addIssue(10, "OCSP response signature or signer authorization could not be verified")
	}
	if info.OCSPVerified {
		switch info.OCSPFreshness {
		case "stale":
			addIssue(5, "stapled OCSP response is stale")
		case "future":
			addIssue(5, "stapled OCSP response is not yet valid")
		case "invalid":
			addIssue(5, "stapled OCSP response has an invalid validity interval")
		case "unknown":
			addIssue(3, "stapled OCSP response has no nextUpdate; freshness cannot be confirmed")
		}
		if info.OCSPStatus == "unknown" {
			addIssue(3, "OCSP responder reported unknown certificate status")
		}
	}
	if info.OCSPStatus == "revoked" && info.OCSPVerified {
		addIssue(100, "certificate has been revoked")
	}
	if score < 0 {
		score = 0
	}
	return score, gradeForScore(score), issues
}

func gradeForScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
