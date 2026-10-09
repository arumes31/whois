package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"whois/internal/model"
)

func ocspCertificate(t *testing.T, template, issuer *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if issuer == nil {
		issuer, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func ocspTestChain(t *testing.T, now time.Time) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	issuer, key := ocspCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OCSP test CA"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:     true, BasicConstraintsValid: true,
	}, nil, nil)
	leaf, _ := ocspCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		DNSNames:    []string{"example.test"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuer, key)
	return []*x509.Certificate{leaf, issuer}, key
}

func TestOCSPFreshness(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	chain, key := ocspTestChain(t, now)
	for _, tc := range []struct {
		name                   string
		thisUpdate, nextUpdate time.Time
		want                   string
	}{
		{"current", now.Add(-time.Hour), now.Add(time.Hour), "current"},
		{"this update boundary", now, now.Add(time.Hour), "current"},
		{"stale", now.Add(-2 * time.Hour), now.Add(-time.Hour), "stale"},
		{"next update boundary", now.Add(-time.Hour), now, "stale"},
		{"future", now.Add(time.Minute), now.Add(time.Hour), "future"},
		{"reversed interval", now.Add(-time.Hour), now.Add(-2 * time.Hour), "invalid"},
		{"missing next update", now.Add(-time.Hour), time.Time{}, "unknown"},
		{"missing this update", time.Time{}, now.Add(time.Hour), "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ocsp.CreateResponse(chain[1], chain[1], ocsp.Response{
				Status: ocsp.Good, SerialNumber: chain[0].SerialNumber,
				ThisUpdate: tc.thisUpdate, NextUpdate: tc.nextUpdate,
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			info := &model.SSLInfo{Verified: true, HostnameValid: true, OCSPStapled: true}
			inspectOCSP(info, raw, chain, now)
			if info.OCSPStatus != "good" || !info.OCSPVerified || info.OCSPFreshness != tc.want {
				t.Fatalf("OCSP result = %#v; want authenticated good with freshness %q", info, tc.want)
			}
			if !tc.thisUpdate.IsZero() && info.OCSPThisUpdate != tc.thisUpdate.Format(time.RFC3339) {
				t.Fatalf("this_update = %q", info.OCSPThisUpdate)
			}
			if tc.nextUpdate.IsZero() && info.OCSPNextUpdate != "" {
				t.Fatalf("invented next update: %q", info.OCSPNextUpdate)
			}
			score, _, issues := scoreTLS(info, chain[0], tls.TLS_AES_128_GCM_SHA256)
			if tc.want == "current" && (score != 100 || len(issues) != 0) {
				t.Fatalf("current response: score=%d issues=%v", score, issues)
			}
			if tc.want != "current" && (score == 100 || len(issues) == 0) {
				t.Fatalf("unreliable freshness was not surfaced: score=%d issues=%v", score, issues)
			}
		})
	}
}

func TestOCSPDelegatedSignerAuthorization(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	chain, issuerKey := ocspTestChain(t, now)
	for _, tc := range []struct {
		name          string
		eku           []x509.ExtKeyUsage
		usage         x509.KeyUsage
		before, after time.Time
		verified      bool
	}{
		{"authorized", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour), true},
		{"content commitment", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageContentCommitment, now.Add(-time.Hour), now.Add(time.Hour), true},
		{"no EKU", nil, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour), false},
		{"wrong EKU", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour), false},
		{"expired", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageDigitalSignature, now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		{"not yet valid", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageDigitalSignature, now.Add(time.Minute), now.Add(time.Hour), false},
		{"wrong key usage", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageKeyEncipherment, now.Add(-time.Hour), now.Add(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responder, key := ocspCertificate(t, &x509.Certificate{
				SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Delegated responder"},
				NotBefore: tc.before, NotAfter: tc.after, ExtKeyUsage: tc.eku, KeyUsage: tc.usage,
			}, chain[1], issuerKey)
			raw, err := ocsp.CreateResponse(chain[1], responder, ocsp.Response{
				Status: ocsp.Good, SerialNumber: chain[0].SerialNumber, Certificate: responder,
				ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			info := &model.SSLInfo{Verified: true, HostnameValid: true, OCSPStapled: true}
			inspectOCSP(info, raw, chain, now)
			if info.OCSPVerified != tc.verified {
				t.Fatalf("verified=%v; want %v; error=%s", info.OCSPVerified, tc.verified, info.OCSPVerificationError)
			}
			if !tc.verified {
				score, _, issues := scoreTLS(info, chain[0], tls.TLS_AES_128_GCM_SHA256)
				if info.OCSPVerificationError == "" || score == 100 || len(issues) == 0 {
					t.Fatalf("untrusted staple lacks finding: %#v, %d, %v", info, score, issues)
				}
			}
		})
	}
}

func TestOCSPRejectsUnboundSigners(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	chain, key := ocspTestChain(t, now)
	otherChain, otherKey := ocspTestChain(t, now)
	otherResponder, _ := ocspCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "Another responder"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}, chain[1], key)
	for _, tc := range []struct {
		name              string
		issuer, responder *x509.Certificate
		signer            *ecdsa.PrivateKey
		chain             []*x509.Certificate
	}{
		{"wrong issuer", otherChain[1], otherChain[1], otherKey, []*x509.Certificate{chain[0], otherChain[1]}},
		{"responder identity mismatch", chain[1], otherResponder, key, chain},
		{"issuer missing", chain[1], chain[1], key, chain[:1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ocsp.CreateResponse(tc.issuer, tc.responder, ocsp.Response{
				Status: ocsp.Good, SerialNumber: chain[0].SerialNumber,
				ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
			}, tc.signer)
			if err != nil {
				t.Fatal(err)
			}
			info := &model.SSLInfo{OCSPStapled: true}
			inspectOCSP(info, raw, tc.chain, now)
			if info.OCSPVerified || info.OCSPVerificationError == "" {
				t.Fatalf("unbound signer accepted: %#v", info)
			}
		})
	}
	info := &model.SSLInfo{OCSPStapled: true}
	inspectOCSP(info, []byte("not an OCSP response"), chain, now)
	if info.OCSPVerified || info.OCSPVerificationError == "" {
		t.Fatalf("malformed staple accepted: %#v", info)
	}
}

func TestOCSPStaleRevocationRemainsCritical(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	chain, key := ocspTestChain(t, now)
	raw, err := ocsp.CreateResponse(chain[1], chain[1], ocsp.Response{
		Status: ocsp.Revoked, SerialNumber: chain[0].SerialNumber,
		ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(-time.Hour), RevokedAt: now.Add(-24 * time.Hour),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	info := &model.SSLInfo{Verified: true, HostnameValid: true, OCSPStapled: true}
	inspectOCSP(info, raw, chain, now)
	score, grade, issues := scoreTLS(info, chain[0], tls.TLS_AES_128_GCM_SHA256)
	if info.OCSPStatus != "revoked" || info.OCSPFreshness != "stale" || score != 0 || grade != "F" || !slices.Contains(issues, "certificate has been revoked") {
		t.Fatalf("stale revocation lost: %#v, score=%d grade=%s issues=%v", info, score, grade, issues)
	}
}

func TestCertificateInfoIncludesIPSANs(t *testing.T) {
	chain, _ := ocspTestChain(t, time.Now())
	info := certificateInfo(chain[0])
	if !slices.Equal(info.IPAddresses, []string{"192.0.2.1", "2001:db8::1"}) || !slices.Equal(info.DNSNames, []string{"example.test"}) {
		t.Fatalf("certificate SANs = %#v", info)
	}
}
