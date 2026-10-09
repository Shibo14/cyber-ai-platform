package workeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
)

type blockingAuditWriter func([]byte) (int, error)

func (f blockingAuditWriter) Write(p []byte) (int, error) { return f(p) }

func workerAuditOutcomes(t *testing.T, log string) []string {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(log))
	var outcomes []string
	for {
		var event map[string]string
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid audit JSON: %v", err)
		}
		if event["event"] != "worker_identity" {
			continue // PEP execution results are separate from identity checks.
		}
		if event["outcome"] == "allowed" {
			t.Fatal("worker identity audit recorded success before final authentication decision")
		}
		outcomes = append(outcomes, event["outcome"])
	}
	return outcomes
}

// Every stage has its own validity guard. Advancing the clock in that guard's
// last blocking dependency must deny the *next* boundary, even when earlier
// stages legitimately ran with a still-valid identity.
var expiryStages = []struct {
	name          string
	guard         int
	maxTX, maxPDP int
}{
	{"context", 1, 0, 0},
	{"worker entry", 1, 0, 0},
	{"before DB", 2, 0, 0},
	{"before PDP", 3, 1, 0},
	{"before tool", 4, 1, 1},
	{"recovery result", 4, 0, 1},
}

func assertExpiredBoundary(t *testing.T, f *fixture, s *Session, ctx context.Context, stage string, maxTX, maxPDP int) {
	t.Helper()
	g := protected(f)
	var err error
	switch stage {
	case "context":
		var got context.Context
		got, err = s.WorkerContext(context.Background())
		if got != nil {
			t.Fatal("expired identity returned WorkerContext")
		}
	case "recovery result":
		var request authorization.WorkerRequest
		request, err = g.p.ResolveWorker(ctx, g.request.DelegationID)
		if request != (authorization.WorkerRequest{}) {
			t.Fatal("expired identity returned recovery authority")
		}
	default:
		err = g.p.ExecuteWorker(ctx, g.request, g.db)
	}
	if err == nil || g.db.runs != 0 || g.db.a.Consumed || g.db.txs > maxTX || g.calls > maxPDP {
		t.Fatalf("expired evidence crossed boundary: err=%v tx=%d PDP=%d tool=%d consumed=%v", err, g.db.txs, g.calls, g.db.runs, g.db.a.Consumed)
	}
}

func TestSlowAuditRejectsExpiredSVID(t *testing.T) {
	for _, side := range []string{"peer", "local"} {
		t.Run(side, func(t *testing.T) {
			for _, stage := range expiryStages {
				t.Run(stage.name, func(t *testing.T) {
					f := newFixture(t)
					expires := f.now.Add(time.Minute)
					short := func(c *x509.Certificate) { c.NotAfter = expires }
					peer := f.cert(t, "spiffe://fixture.test/worker-a", nil)
					if side == "peer" {
						peer = f.cert(t, "spiffe://fixture.test/worker-a", short)
					} else {
						f.source.material.SVID = f.cert(t, "spiffe://fixture.test/service", short)
					}
					s, err := f.connect(t, peer)
					if err != nil {
						t.Fatal(err)
					}
					ctx, err := s.WorkerContext(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					f.log.Reset()
					calls := 0
					s.bridge.config.Audit = audit.New(blockingAuditWriter(func(p []byte) (int, error) {
						calls++
						if calls == stage.guard {
							f.now = expires // NotAfter is exclusive, including after audit.
						}
						return f.log.Write(p)
					}), "event", "outcome", "failure_class")
					assertExpiredBoundary(t, f, s, ctx, stage.name, stage.maxTX, stage.maxPDP)
					outcomes := workerAuditOutcomes(t, f.log.String())
					if calls != stage.guard+1 || strings.Join(outcomes, ",") != strings.Repeat("pending,", stage.guard)+"denied" {
						t.Fatalf("incorrect slow audit result sequence: %v", outcomes)
					}
				})
			}
		})
	}
}

func TestAcceptRechecksEvidenceAfterAudit(t *testing.T) {
	for _, side := range []string{"peer", "local"} {
		t.Run(side, func(t *testing.T) {
			f := newFixture(t)
			expires := f.now.Add(time.Minute)
			short := func(c *x509.Certificate) { c.NotAfter = expires }
			peer := f.cert(t, "spiffe://fixture.test/worker-a", nil)
			if side == "peer" {
				peer = f.cert(t, "spiffe://fixture.test/worker-a", short)
			} else {
				f.source.material.SVID = f.cert(t, "spiffe://fixture.test/service", short)
			}
			f.config.Audit = audit.New(blockingAuditWriter(func(p []byte) (int, error) {
				f.now = expires
				return f.log.Write(p)
			}), "event", "outcome", "failure_class")
			if s, err := f.connect(t, peer); err != ErrDenied || s != nil {
				t.Fatalf("expired evidence yielded session after audit: %v", err)
			}
			if outcomes := workerAuditOutcomes(t, f.log.String()); strings.Join(outcomes, ",") != "pending,denied" {
				t.Fatalf("incorrect rejected handshake audit: %v", outcomes)
			}
		})
	}
}

func TestAuditWriteFailureNeverRecordsAuthenticationSuccess(t *testing.T) {
	for _, failure := range []struct {
		name           string
		expire         bool
		persistFailure bool
	}{
		{"pending write fails", false, false},
		{"pending persisted then error", false, true},
		{"expiry denial write fails", true, false},
		{"expiry denial persisted then error", true, true},
	} {
		t.Run(failure.name, func(t *testing.T) {
			for _, stage := range expiryStages {
				t.Run(stage.name, func(t *testing.T) {
					f := newFixture(t)
					expires := f.now.Add(time.Minute)
					s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", func(c *x509.Certificate) { c.NotAfter = expires }))
					if err != nil {
						t.Fatal(err)
					}
					ctx, err := s.WorkerContext(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					f.log.Reset()
					calls, failAt := 0, stage.guard
					if failure.expire {
						failAt++ // The pending write succeeds; the later denial write fails.
					}
					s.bridge.config.Audit = audit.New(blockingAuditWriter(func(p []byte) (int, error) {
						calls++
						if failure.expire && calls == stage.guard {
							f.now = expires
						}
						if calls == failAt {
							written := 0
							if failure.persistFailure {
								written, _ = f.log.Write(p)
							}
							return written, errors.New("credential=audit-sink-secret")
						}
						return f.log.Write(p)
					}), "event", "outcome", "failure_class")
					assertExpiredBoundary(t, f, s, ctx, stage.name, stage.maxTX, stage.maxPDP)
					outcomes := workerAuditOutcomes(t, f.log.String())
					want := strings.Repeat("pending,", stage.guard-1)
					if failure.expire || failure.persistFailure {
						want += "pending,"
					}
					if failure.expire && failure.persistFailure {
						want += "denied,"
					}
					if calls != failAt || strings.Join(outcomes, ",") != strings.TrimSuffix(want, ",") {
						t.Fatalf("incorrect stored audit after write failure: %v (calls=%d)", outcomes, calls)
					}
					if strings.Contains(f.log.String(), "audit-sink-secret") {
						t.Fatal("audit dependency error leaked")
					}
				})
			}
		})
	}
}

func TestNeutralAuditPreservesSuccessfulAuthentication(t *testing.T) {
	f := newFixture(t)
	s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.WorkerContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g := protected(f)
	if err := g.p.ExecuteWorker(ctx, g.request, g.db); err != nil || g.db.runs != 1 || !g.db.a.Consumed || g.calls == 0 {
		t.Fatalf("valid authentication/authorized execution changed: %v", err)
	}
	outcomes := workerAuditOutcomes(t, f.log.String())
	if len(outcomes) == 0 {
		t.Fatal("identity checks were not audited")
	}
	for _, outcome := range outcomes {
		if outcome != "pending" {
			t.Fatalf("pre-final identity audit is not neutral: %s", outcome)
		}
	}
}

func intermediatePeer(t *testing.T, f *fixture) tls.Certificate {
	t.Helper()
	intermediate := *f.ca
	intermediate.NotAfter = f.now.Add(time.Minute)
	intermediate.Subject = pkix.Name{CommonName: "short-lived fixture intermediate"}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &intermediate, f.ca, pub, f.key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &fixture{now: f.now, ca: parsed, key: key}
	peer := issuer.cert(t, "spiffe://fixture.test/worker-a", nil)
	peer.Certificate = append(peer.Certificate, der)
	return peer
}

func TestIntermediateExpiryAfterBlockingDependency(t *testing.T) {
	for _, dependency := range []string{"mapping", "status", "audit"} {
		t.Run(dependency, func(t *testing.T) {
			for _, stage := range expiryStages {
				t.Run(stage.name, func(t *testing.T) {
					f := newFixture(t)
					expires := f.now.Add(time.Minute)
					s, err := f.connect(t, intermediatePeer(t, f))
					if err != nil {
						t.Fatal(err)
					}
					if !s.identity.ChainNotAfter.Equal(expires) || !s.identity.NotAfter.After(expires) {
						t.Fatal("fixture must retain a valid leaf after its intermediate expires")
					}
					ctx, err := s.WorkerContext(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					calls := 0
					block := func() {
						calls++
						if calls == stage.guard {
							f.now = expires
						}
					}
					switch dependency {
					case "mapping":
						s.bridge.config.Mapper = mapperDouble(func(context.Context, Identity) (authorization.ActorPrincipal, error) {
							block()
							return "worker-a", nil
						})
					case "status":
						s.bridge.config.Status = statusDouble(func(context.Context, Identity) (bool, error) { block(); return true, nil })
					case "audit":
						s.bridge.config.Audit = audit.New(blockingAuditWriter(func(p []byte) (int, error) { block(); return len(p), nil }), "event")
					}
					assertExpiredBoundary(t, f, s, ctx, stage.name, stage.maxTX, stage.maxPDP)
					if calls < stage.guard {
						t.Fatal("blocking dependency was not reached")
					}
				})
			}
		})
	}
}

func rawSAN(t *testing.T, names ...asn1.RawValue) []byte {
	t.Helper()
	der, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRawDERSPIFFESAN(t *testing.T) {
	uri := func(s string) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(s)}
	}
	const valid = "spiffe://fixture.test/worker-a"
	cases := []struct {
		name string
		der  []byte
		pass bool
	}{
		{"valid", rawSAN(t, uri(valid)), true},
		{"trailing fragment delimiter", rawSAN(t, uri(valid+"#")), false},
		{"fragment", rawSAN(t, uri(valid+"#worker-b")), false},
		{"query", rawSAN(t, uri(valid+"?worker=b")), false},
		{"empty query", rawSAN(t, uri(valid+"?")), false},
		{"userinfo", rawSAN(t, uri("spiffe://user@fixture.test/worker-a")), false},
		{"empty userinfo", rawSAN(t, uri("spiffe://@fixture.test/worker-a")), false},
		{"percent normalization", rawSAN(t, uri("spiffe://fixture.test/%77orker-a")), false},
		{"malformed percent", rawSAN(t, uri(valid+"%")), false},
		{"raw control character", rawSAN(t, uri(valid+"\x00")), false},
		{"non IA5 character", rawSAN(t, uri(valid+"é")), false},
		{"multiple URI names", rawSAN(t, uri(valid), uri(valid)), false},
		{"no URI name", rawSAN(t, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte("localhost")}), false},
		{"constructed URI name", rawSAN(t, asn1.RawValue{Class: 2, Tag: 6, IsCompound: true, Bytes: []byte(valid)}), false},
		{"wrong URI class", rawSAN(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: []byte(valid)}), false},
		{"trailing DER", append(rawSAN(t, uri(valid)), 0), false},
		{"truncated DER", []byte{0x30, 0x03, 0x86, 0x02, 'x'}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// ExtraExtensions puts these exact GeneralName bytes in the signed
			// certificate. The hostile URI never passes through url.Parse here.
			peer := f.cert(t, valid, func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: tc.der}}
			})
			id, err := f.config.Verifier.Verify(context.Background(), peer.Certificate, f.source.material.Bundles, f.now, x509.ExtKeyUsageClientAuth)
			if tc.pass {
				if err != nil || id.ID != valid {
					t.Fatalf("valid raw SAN rejected: %v", err)
				}
			} else if err != ErrDenied || id != (Identity{}) {
				t.Fatalf("malformed signed SAN verified: %v", err)
			}
			mapped := 0
			f.config.Mapper = mapperDouble(func(context.Context, Identity) (authorization.ActorPrincipal, error) {
				mapped++
				return "worker-a", nil
			})
			s, err := f.connect(t, peer)
			if tc.pass {
				if err != nil || s == nil {
					t.Fatalf("valid transport rejected: %v", err)
				}
			} else if err == nil || s != nil || mapped != 0 {
				t.Fatalf("malformed SAN reached identity mapping/session: mapped=%d err=%v", mapped, err)
			}
		})
	}
}
