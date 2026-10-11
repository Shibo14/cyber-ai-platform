package workeridentity

import (
	"context"
	"crypto/x509"
	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/ratelimit"
	"errors"
	"testing"
	"time"
)

type costPolicyDouble func(context.Context, authorization.Execution, authorization.AdmissionStage) (ratelimit.Quote, error)

func (f costPolicyDouble) Quote(c context.Context, e authorization.Execution, s authorization.AdmissionStage) (ratelimit.Quote, error) {
	return f(c, e, s)
}

type accountingDouble func(context.Context, ratelimit.Debit) (ratelimit.Receipt, error)

func (f accountingDouble) TryDebit(c context.Context, d ratelimit.Debit) (ratelimit.Receipt, error) {
	return f(c, d)
}

type costPrivacy struct{}

func (costPrivacy) Reference(context.Context, string, string) (string, error) {
	return "fixture-safe-reference", nil
}

type costTaxonomy struct{}

func (costTaxonomy) Validate(context.Context, audit.Input) error { return nil }

type costWriter func(context.Context, audit.Event) error

func (f costWriter) Write(c context.Context, e audit.Event) error { return f(c, e) }

type admissionGuard func(context.Context, authorization.Execution, authorization.AdmissionStage) error

func (f admissionGuard) Admit(c context.Context, e authorization.Execution, s authorization.AdmissionStage) error {
	return f(c, e, s)
}

func TestQueueCostAdmissionAndACKRecovery(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed ACK recovery", true: "bounded cost denial"}[deny], func(t *testing.T) {
			f := newFixture(t)
			g := protected(f)
			charges := 0
			bound, err := authorization.BindAdmission(g.p, admissionGuard(func(context.Context, authorization.Execution, authorization.AdmissionStage) error {
				charges++
				if deny {
					return ratelimit.ErrDenied
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			g.p = bound
			consumer, broker := consumer(t, f, g)
			s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", nil))
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.WorkerContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !deny {
				broker.ackErr = errors.New("ACK unavailable")
			}
			_, _ = consumer.Handle(ctx, broker.d)
			broker.ackErr = nil
			before := g.calls
			_, _ = consumer.Recover(ctx, 1, time.Second)
			if g.calls <= before {
				t.Fatal("recovery skipped fresh authorization")
			}
			if deny {
				if g.db.runs != 0 || g.db.a.Consumed || broker.dlq != 1 || charges != 2 {
					t.Fatal("cost denial bypass/infinite retry")
				}
			} else if g.db.runs != 1 || !g.db.a.Consumed || charges != 1 || broker.acks != 2 {
				t.Fatal("ACK recovery repeated business cost/operation")
			}
		})
	}
}
func TestCostBoundaryWithLiveWorkerIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "expired during limiter", "expired during audit", "expired during fresh PDP", "audit failure", "approval expired", "delegation expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			expiry := f.now.Add(time.Minute)
			s, err := f.connect(t, f.cert(t, "spiffe://fixture.test/worker-a", func(c *x509.Certificate) {
				if mode != "approval expired" && mode != "delegation expired" {
					c.NotAfter = expiry
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.WorkerContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			g := protected(f)
			if mode == "approval expired" {
				g.db.a.ExpiresAt = expiry
			}
			if mode == "delegation expired" {
				g.store.d.ExpiresAt = expiry
			}
			b, _ := audit.NewBuilder(costPrivacy{}, costTaxonomy{}, func() time.Time { return f.now })
			r, _ := audit.NewRecorder(b, costWriter(func(_ context.Context, e audit.Event) error {
				if e.Data().Kind == "cost_debit" {
					if mode == "expired during audit" {
						f.now = expiry
					}
					if mode == "audit failure" {
						return errors.New("private sink")
					}
				}
				if e.Data().Result == audit.Succeeded {
					t.Fatal("false authentication success")
				}
				return nil
			}))
			gate, _ := ratelimit.New(costPolicyDouble(func(context.Context, authorization.Execution, authorization.AdmissionStage) (ratelimit.Quote, error) {
				return ratelimit.Quote{Bucket: "fixture", Epoch: "fixture", Version: "fixture", Attempt: "fixture", Cost: 1, Limit: 1}, nil
			}), accountingDouble(func(_ context.Context, d ratelimit.Debit) (ratelimit.Receipt, error) {
				if mode == "expired during limiter" || mode == "approval expired" || mode == "delegation expired" {
					f.now = expiry
				}
				if mode == "expired during fresh PDP" {
					g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
						f.now = expiry
						return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
					})
				}
				return ratelimit.Receipt{Debit: d, Outcome: ratelimit.Admitted}, nil
			}), r)
			g.p, err = authorization.BindAdmission(g.p, gate)
			if err != nil {
				t.Fatal(err)
			}
			err = g.p.ExecuteWorker(ctx, g.request, g.db)
			if mode == "valid" {
				if err != nil || g.db.runs != 1 || !g.db.a.Consumed {
					t.Fatal(err)
				}
			} else if err == nil || g.db.runs != 0 || g.db.a.Consumed {
				t.Fatal("slow cost boundary bypassed validity")
			}
			workerAuditOutcomes(t, f.log.String())
		})
	}
}
