package workeridentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/authorization"
)

func TestMTLSIdentityDenials(t *testing.T) {
	for _, name := range []string{"valid", "TLS12", "no certificate", "invalid signature", "untrusted chain", "expired", "not yet valid", "missing ID", "multiple IDs", "malformed ID", "wrong domain", "unknown mapping", "missing bundle", "source failure", "mapper failure", "withdrawn", "status failure", "CA as worker", "excess lifetime", "wrong key", "missing digital signature", "wrong EKU"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			id := "spiffe://fixture.test/worker-a"
			var mutate func(*x509.Certificate)
			switch name {
			case "TLS12":
				f.config.MinTLSVersion = tls.VersionTLS12
			case "expired":
				mutate = func(c *x509.Certificate) { c.NotAfter = f.now.Add(-time.Second) }
			case "not yet valid":
				mutate = func(c *x509.Certificate) { c.NotBefore = f.now.Add(time.Minute) }
			case "missing ID":
				mutate = func(c *x509.Certificate) { c.URIs = nil }
			case "multiple IDs":
				mutate = func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) }
			case "malformed ID":
				id = "spiffe://fixture.test/a/../worker-a"
			case "wrong domain":
				id = "spiffe://other.test/worker-a"
			case "unknown mapping":
				id = "spiffe://fixture.test/unknown"
			case "missing bundle":
				f.source.material.Bundles = nil
			case "source failure":
				f.source.err = errors.New("credential=source-secret")
			case "mapper failure":
				f.config.Mapper = mapperDouble(func(context.Context, Identity) (authorization.ActorPrincipal, error) {
					return "", errors.New("credential=mapper-secret")
				})
			case "withdrawn":
				f.config.Status = statusDouble(func(context.Context, Identity) (bool, error) { return false, nil })
			case "status failure":
				f.config.Status = statusDouble(func(context.Context, Identity) (bool, error) { return false, errors.New("credential=status-secret") })
			case "CA as worker":
				mutate = func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }
			case "excess lifetime":
				mutate = func(c *x509.Certificate) { c.NotAfter = f.now.Add(3 * time.Hour) }
			case "missing digital signature":
				mutate = func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }
			case "wrong EKU":
				mutate = func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }
			}
			cert := f.cert(t, id, mutate)
			switch name {
			case "no certificate":
				cert = tls.Certificate{}
			case "invalid signature":
				cert.Certificate[0][len(cert.Certificate[0])-1] ^= 1
			case "untrusted chain":
				cert = newFixture(t).cert(t, id, nil)
			case "wrong key":
				cert.PrivateKey = f.cert(t, id, nil).PrivateKey
			}
			s, err := f.connect(t, cert)
			if name == "valid" || name == "TLS12" {
				if err != nil {
					t.Fatal(err)
				}
				ctx, err := s.WorkerContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := (&authorization.PEP{}).VerifyWorker(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || s != nil {
				t.Fatal("untrusted transport created a session")
			}
			for _, secret := range []string{"source-secret", "mapper-secret", "status-secret", "BEGIN", "spiffe://", "x509:"} {
				if strings.Contains(f.log.String(), secret) || err != nil && strings.Contains(err.Error(), secret) {
					t.Fatal("sensitive output")
				}
			}
		})
	}
}

func TestSessionRefreshAndContextExpiry(t *testing.T) {
	for _, name := range []string{"expired", "refresh failure", "bundle removed", "bundle replaced", "local SVID expired", "mapping changed", "withdrawn", "closed", "slow mapping"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			active := true
			f.config.Status = statusDouble(func(context.Context, Identity) (bool, error) { return active, nil })
			s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", func(c *x509.Certificate) { c.NotAfter = f.now.Add(time.Minute) }))
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.WorkerContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "expired":
				f.now = f.now.Add(time.Minute)
			case "refresh failure":
				f.source.err = errors.New("credential=refresh-secret")
			case "bundle removed":
				f.source.material.Bundles = nil
			case "bundle replaced":
				f.source.material.Bundles = map[string]*x509.CertPool{"fixture.test": newFixture(t).roots}
			case "local SVID expired":
				f.source.material.SVID = f.cert(t, "spiffe://fixture.test/service", func(c *x509.Certificate) { c.NotAfter = f.now.Add(-time.Second) })
			case "mapping changed":
				s.bridge.config.Mapper = mapperDouble(func(context.Context, Identity) (authorization.ActorPrincipal, error) { return "worker-b", nil })
			case "withdrawn":
				active = false
			case "closed":
				_ = s.Close()
			case "slow mapping":
				s.bridge.config.Mapper = mapperDouble(func(context.Context, Identity) (authorization.ActorPrincipal, error) {
					f.now = f.now.Add(2 * time.Minute)
					return "worker-a", nil
				})
			}
			if err := (&authorization.PEP{}).VerifyWorker(ctx); err == nil {
				t.Fatal("stale context accepted")
			}
			if got, err := s.WorkerContext(context.Background()); err == nil || got != nil {
				t.Fatal("failed refresh returned context")
			}
		})
	}
}

func TestNoCertificateOrStateImport(t *testing.T) {
	var s Session
	if ctx, err := s.WorkerContext(context.Background()); ctx != nil || err == nil {
		t.Fatal("zero session grants authority")
	}
	f := newFixture(t)
	b, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := b.Accept(context.Background(), nil); s != nil || err == nil {
		t.Fatal("nil transport accepted")
	}
	ctx := authorization.WithVerifiedWorkerCheck(context.Background(), "worker-a", nil)
	if (&authorization.PEP{}).VerifyWorker(ctx) == nil {
		t.Fatal("nil guard downgraded to marker")
	}
}

func TestSPIFFEIDGrammar(t *testing.T) {
	for _, id := range []string{"https://fixture.test/a", "spiffe://fixture.test/", "spiffe://fixture.test/a//b", "spiffe://fixture.test/a/", "spiffe://fixture.test/a?x=1", "spiffe://fixture.test/a#f", "spiffe://user@fixture.test/a", "spiffe://fixture.test:443/a", "spiffe://fixture.test/a%2Fb", "spiffe://fixture.test/./a", "spiffe://fixture.test/a b"} {
		u, err := url.Parse(id)
		if err == nil && spiffeID(u) {
			t.Errorf("accepted %s", id)
		}
	}
}

func TestSafeClassification(t *testing.T) {
	if Classify(errors.New("credential=hidden")) != ErrDependency {
		t.Fatal("unsafe error")
	}
	for _, err := range []error{nil, ErrDenied, ErrDependency, ErrConfiguration, ErrAudit} {
		if Classify(err) != err {
			t.Fatal("wrong classification")
		}
	}
}
