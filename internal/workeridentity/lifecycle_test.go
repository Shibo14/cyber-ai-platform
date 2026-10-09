package workeridentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
)

type sinkFailure struct{}

func (sinkFailure) Write([]byte) (int, error) {
	return 0, errors.New("credential=private-key-material")
}

func TestConfigurationFailsClosed(t *testing.T) {
	for _, name := range []string{"source", "verifier", "mapper", "audit", "timeout", "TLS version"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			switch name {
			case "source":
				f.config.Source = nil
			case "verifier":
				f.config.Verifier = nil
			case "mapper":
				f.config.Mapper = nil
			case "audit":
				f.config.Audit = nil
			case "timeout":
				f.config.HandshakeTimeout = 0
			case "TLS version":
				f.config.MinTLSVersion = tls.VersionTLS10
			}
			if b, err := New(f.config); b != nil || err != ErrConfiguration {
				t.Fatal("invalid config accepted")
			}
		})
	}
	for _, d := range []string{"", "UPPER", "domain:443", "user@domain", "domain/path"} {
		if v, err := NewX509Verifier([]string{d}, time.Hour); v != nil || err != ErrConfiguration {
			t.Fatal("invalid trust domain accepted")
		}
	}
	if v, err := NewX509Verifier([]string{"fixture.test"}, 0); v != nil || err != ErrConfiguration {
		t.Fatal("unbounded lifetime accepted")
	}
}

func TestSourceAndAuditFailures(t *testing.T) {
	for _, name := range []string{"missing key", "wrong key", "empty chain", "corrupt chain", "empty roots", "audit failure"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			switch name {
			case "missing key":
				f.source.material.SVID.PrivateKey = nil
			case "wrong key":
				f.source.material.SVID.PrivateKey = f.cert(t, "spiffe://fixture.test/service", nil).PrivateKey
			case "empty chain":
				f.source.material.SVID.Certificate = nil
			case "corrupt chain":
				f.source.material.SVID.Certificate = [][]byte{[]byte("credential=bad-certificate")}
			case "empty roots":
				f.source.material.Bundles["fixture.test"] = x509.NewCertPool()
			case "audit failure":
				f.config.Audit = audit.New(sinkFailure{}, "event")
			}
			s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
			if err == nil || s != nil {
				t.Fatal("failed dependency returned session")
			}
			if strings.Contains(err.Error(), "credential") || strings.Contains(f.log.String(), "bad-certificate") {
				t.Fatal("raw material escaped")
			}
		})
	}
}

func TestStalledHandshakeIsBounded(t *testing.T) {
	f := newFixture(t)
	f.config.HandshakeTimeout = 20 * time.Millisecond
	b, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	start := time.Now()
	s, err := b.Accept(context.Background(), server)
	if s != nil || err != ErrDependency || time.Since(start) > time.Second {
		t.Fatal("stalled handshake not bounded")
	}
}

func TestIdentityDoesNotSurviveSlowRecoveryPDP(t *testing.T) {
	f := newFixture(t)
	g := protected(f)
	s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", func(c *x509.Certificate) { c.NotAfter = f.now.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.WorkerContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		f.now = f.now.Add(2 * time.Minute)
		return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	if _, err := g.p.ResolveWorker(ctx, g.request.DelegationID); err == nil {
		t.Fatal("expired worker received recovery authority")
	}
	if g.db.txs != 0 {
		t.Fatal("preflight entered DB")
	}
}

func TestCancelledSourceAndRenewedMaterial(t *testing.T) {
	f := newFixture(t)
	s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.WorkerContext(ctx); got != nil || err == nil {
		t.Fatal("cancelled verification accepted")
	}
	// Simulate an external source installing a new local SVID. This is not a
	// production rotation scheduler or proof of issuer integration.
	f.source.material.SVID = f.cert(t, "spiffe://fixture.test/service", nil)
	if _, err := s.WorkerContext(context.Background()); err != nil {
		t.Fatal("valid refreshed source rejected")
	}
}

func TestSlowIdentityRefreshCannotExtendApproval(t *testing.T) {
	f := newFixture(t)
	g := protected(f)
	s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.WorkerContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g.db.a.ExpiresAt = f.now.Add(time.Second)
	g.db.beforeExecute = func() {
		f.source.onCurrent = func() { f.now = f.now.Add(2 * time.Second); f.source.onCurrent = nil }
	}
	if err := g.p.ExecuteWorker(ctx, g.request, g.db); err == nil || g.db.runs != 0 || g.db.a.Consumed {
		t.Fatal("slow identity refresh extended approval or failed to roll back consumption")
	}
}

func TestSlowIdentityRefreshCannotExtendRecoveryDelegation(t *testing.T) {
	f := newFixture(t)
	g := protected(f)
	s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.WorkerContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g.store.d.ExpiresAt = f.now.Add(time.Second)
	g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		f.source.onCurrent = func() { f.now = f.now.Add(2 * time.Second); f.source.onCurrent = nil }
		return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	if _, err := g.p.ResolveWorker(ctx, g.request.DelegationID); err == nil {
		t.Fatal("slow refresh extended delegation")
	}
}
