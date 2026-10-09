package workeridentity

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"net/url"
	"strings"
	"time"
)

// X509Verifier implements SPIFFE X.509 leaf/chain verification. The deployment
// supplies approved domains and a positive maximum SVID lifetime; no issuer,
// organization-specific path format or duration is selected here.
type X509Verifier struct {
	domains     map[string]bool
	maxLifetime time.Duration
}

func NewX509Verifier(domains []string, maxLifetime time.Duration) (*X509Verifier, error) {
	if len(domains) == 0 || maxLifetime <= 0 {
		return nil, ErrConfiguration
	}
	v := &X509Verifier{domains: make(map[string]bool), maxLifetime: maxLifetime}
	for _, d := range domains {
		if !domain(d) {
			return nil, ErrConfiguration
		}
		v.domains[d] = true
	}
	return v, nil
}

func domain(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func spiffeID(u *url.URL) bool {
	if u == nil || u.Scheme != "spiffe" || !domain(u.Host) || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" ||
		len(u.String()) > 2048 || !strings.HasPrefix(u.Path, "/") || u.Path == "/" {
		return false
	}
	for _, part := range strings.Split(u.Path[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Read the original URI GeneralName: x509's parsed URLs have already lost
// representations such as a trailing '#'. Do not authenticate a normalized
// identity until its original signed SAN representation has been validated.
func rawSPIFFEID(leaf *x509.Certificate) (*url.URL, error) {
	var uri *url.URL
	found := false
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		if found {
			return nil, ErrDenied
		}
		found = true
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return nil, ErrDenied
		}
		for names := seq.Bytes; len(names) > 0; {
			var name asn1.RawValue
			names, err = asn1.Unmarshal(names, &name)
			if err != nil || name.Class != asn1.ClassContextSpecific {
				return nil, ErrDenied
			}
			if name.Tag != 6 {
				continue
			}
			raw := string(name.Bytes)
			if uri != nil || name.IsCompound || len(raw) > 2048 || strings.ContainsAny(raw, "#?@%") {
				return nil, ErrDenied
			}
			uri, err = url.Parse(raw)
			if err != nil || !spiffeID(uri) {
				return nil, ErrDenied
			}
		}
	}
	if uri == nil {
		return nil, ErrDenied
	}
	return uri, nil
}

func (v *X509Verifier) Verify(ctx context.Context, raw [][]byte, bundles map[string]*x509.CertPool, now time.Time, usage x509.ExtKeyUsage) (Identity, error) {
	if v == nil || v.maxLifetime <= 0 {
		return Identity{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return Identity{}, ErrDependency
	}
	if len(raw) == 0 || (usage != x509.ExtKeyUsageClientAuth && usage != x509.ExtKeyUsageServerAuth) {
		return Identity{}, ErrDenied
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return Identity{}, ErrDenied
	}
	u, err := rawSPIFFEID(leaf)
	if err != nil || leaf.IsCA ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 ||
		!leaf.NotAfter.After(leaf.NotBefore) || leaf.NotAfter.Sub(leaf.NotBefore) > v.maxLifetime ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return Identity{}, ErrDenied
	}
	criticalUsage := false
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == "2.5.29.15" {
			criticalUsage = ext.Critical
		}
	}
	if !criticalUsage {
		return Identity{}, ErrDenied
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		client, server := false, false
		for _, eku := range leaf.ExtKeyUsage {
			client = client || eku == x509.ExtKeyUsageClientAuth
			server = server || eku == x509.ExtKeyUsageServerAuth
		}
		if !client || !server {
			return Identity{}, ErrDenied
		}
	}
	if !v.domains[u.Host] {
		return Identity{}, ErrDenied
	}
	roots := bundles[u.Host]
	if roots == nil || len(roots.Subjects()) == 0 {
		return Identity{}, ErrDependency
	}
	intermediates := x509.NewCertPool()
	for _, der := range raw[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return Identity{}, ErrDenied
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil || len(chains) == 0 {
		return Identity{}, ErrDenied
	}
	id := Identity{ID: u.String(), TrustDomain: u.Host, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		ChainNotBefore: leaf.NotBefore, ChainNotAfter: leaf.NotAfter}
	for _, cert := range chains[0] {
		if cert.NotBefore.After(id.ChainNotBefore) {
			id.ChainNotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(id.ChainNotAfter) {
			id.ChainNotAfter = cert.NotAfter
		}
	}
	if !id.validAt(now) {
		return Identity{}, ErrDenied
	}
	return id, nil
}
