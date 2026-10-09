package workeridentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/queue"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

const tenantA tenantidentity.TenantID = "a0b1c2d3-e4f5-4678-9abc-def012345678"
const tenantB tenantidentity.TenantID = "b0b1c2d3-e4f5-4678-9abc-def012345678"

type policyDouble func(context.Context, authorization.Execution) (authorization.Decision, error)

func (f policyDouble) Evaluate(c context.Context, e authorization.Execution) (authorization.Decision, error) {
	return f(c, e)
}

type delegationDouble struct{ d authorization.Delegation }

func (s *delegationDouble) Create(_ context.Context, d authorization.Delegation) error {
	s.d = d
	return nil
}
func (s *delegationDouble) Load(_ context.Context, id string) (authorization.Delegation, error) {
	if id != s.d.ID {
		return authorization.Delegation{}, errors.New("not found")
	}
	return s.d, nil
}

type boundaryDouble struct {
	a             authorization.Approval
	txs, runs     int
	beforeExecute func()
}

func (b *boundaryDouble) WithTenantTx(ctx context.Context, fn func(tenantdb.TenantTx) error) error {
	i, ok := tenantidentity.FromContext(ctx)
	if !ok || i.TenantID != b.a.TenantID {
		return authorization.ErrDenied
	}
	b.txs++
	before := b.a
	err := fn(nil)
	if err != nil {
		b.a = before
	}
	return err
}
func (b *boundaryDouble) Load(context.Context, tenantdb.TenantTx, string) (authorization.Approval, error) {
	return b.a, nil
}
func (b *boundaryDouble) Consume(context.Context, tenantdb.TenantTx, string) (bool, error) {
	if b.a.Consumed {
		return false, nil
	}
	b.a.Consumed = true
	if b.beforeExecute != nil {
		b.beforeExecute()
	}
	return true, nil
}
func (b *boundaryDouble) LockState(context.Context, tenantdb.TenantTx, authorization.Execution) (string, error) {
	return "state", nil
}
func (b *boundaryDouble) ExecuteIfState(context.Context, tenantdb.TenantTx, authorization.Execution, string) error {
	b.runs++
	return nil
}

type protectedFixture struct {
	p       *authorization.PEP
	db      *boundaryDouble
	store   *delegationDouble
	request authorization.WorkerRequest
	calls   int
}

func protected(f *fixture) *protectedFixture {
	op := authorization.Operation{Action: "fixture.update", ResourceID: "fixture:object", InputFingerprint: "fixture-input"}
	e := authorization.Execution{TenantID: tenantA, Subject: "user-a", Actor: "worker-a", Operation: op, CorrelationID: "correlation"}
	b := &boundaryDouble{a: authorization.Approval{ID: "approval", TenantID: tenantA, Subject: "user-a", Operation: op, ResourceState: "state", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}}
	s := &delegationDouble{d: authorization.Delegation{ID: "opaque-job", Execution: e, ApprovalID: "approval", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}}
	g := &protectedFixture{db: b, store: s, request: authorization.WorkerRequest{DelegationID: s.d.ID, Operation: op, CorrelationID: e.CorrelationID}}
	g.p = &authorization.PEP{DB: b, Approvals: b, Delegations: s, Audit: f.config.Audit, Now: func() time.Time { return f.now }}
	g.p.Policy = policyDouble(func(ctx context.Context, e authorization.Execution) (authorization.Decision, error) {
		g.calls++
		i, ok := tenantidentity.FromContext(ctx)
		if !ok || i.TenantID != e.TenantID || i.PrincipalID != string(e.Subject) {
			return authorization.Decision{}, nil
		}
		return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	return g
}

func TestTransportDelegationBoundary(t *testing.T) {
	for _, name := range []string{"valid", "wrong worker", "cross tenant", "wrong subject", "actor denied", "subject denied", "PDP failure", "refresh before entry", "refresh during approval", "no marker", "no human downgrade"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			g := protected(f)
			id := "spiffe://fixture.test/worker-a"
			if name == "wrong worker" {
				id = "spiffe://fixture.test/worker-b"
			}
			s, err := f.connect(t, f.cert(t, id, nil))
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.WorkerContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "cross tenant":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "user-a"})
			case "wrong subject":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantA, PrincipalID: "user-b"})
			case "actor denied":
				g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					g.calls++
					return authorization.Decision{SubjectAllowed: true}, nil
				})
			case "subject denied":
				g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					g.calls++
					return authorization.Decision{ActorAllowed: true}, nil
				})
			case "PDP failure":
				g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					g.calls++
					return authorization.Decision{}, errors.New("credential=secret")
				})
			case "refresh before entry":
				f.source.err = errors.New("source unavailable")
			case "refresh during approval":
				g.db.beforeExecute = func() { f.source.err = errors.New("source unavailable") }
			case "no marker":
				ctx = context.Background()
			}
			if name == "no human downgrade" {
				err = g.p.Execute(ctx, authorization.Request{Operation: g.request.Operation, CorrelationID: g.request.CorrelationID, ApprovalID: "approval"}, g.db)
			} else {
				err = g.p.ExecuteWorker(ctx, g.request, g.db)
			}
			if name == "valid" {
				if err != nil || g.db.runs != 1 || !g.db.a.Consumed {
					t.Fatalf("protected execution: %v", err)
				}
			} else {
				if err == nil || g.db.runs != 0 || g.db.a.Consumed {
					t.Fatal("identity bypassed protected execution")
				}
				switch name {
				case "wrong worker", "cross tenant", "wrong subject", "refresh before entry", "no marker", "no human downgrade":
					if g.calls != 0 || g.db.txs != 0 {
						t.Fatal("invalid identity reached PDP/DB")
					}
				}
			}
		})
	}
}

type brokerDouble struct {
	d                        queue.Delivery
	acks, claims, reads, dlq int
	ackErr                   error
}

func (b *brokerDouble) Key(id string) (queue.DeliveryKey, error) {
	return queue.DeliveryKey{Stream: "fixture", Group: "fixture", ID: id}, nil
}
func (b *brokerDouble) Publish(context.Context, queue.Fields) (string, error) { return "1-0", nil }
func (b *brokerDouble) Read(context.Context, int64) ([]queue.Delivery, error) {
	b.reads++
	return []queue.Delivery{b.d}, nil
}
func (b *brokerDouble) Pending(context.Context, int64) ([]queue.Pending, error) {
	return []queue.Pending{{ID: b.d.ID, Consumer: "worker-a", Idle: time.Hour}}, nil
}
func (b *brokerDouble) Claim(context.Context, []string, time.Duration) ([]queue.Delivery, error) {
	b.claims++
	return []queue.Delivery{b.d}, nil
}
func (b *brokerDouble) Ack(context.Context, string) error { b.acks++; return b.ackErr }
func (b *brokerDouble) WriteDLQ(context.Context, queue.DeadLetter) (string, error) {
	b.dlq++
	return "2-0", nil
}

type storeDouble struct{ state queue.State }

func (s *storeDouble) Acquire(context.Context, queue.DeliveryKey) (queue.Lease, error) { return s, nil }
func (s *storeDouble) Load(context.Context) (queue.State, error)                       { return s.state, nil }
func (s *storeDouble) Save(_ context.Context, state queue.State) error                 { s.state = state; return nil }
func (s *storeDouble) Release(context.Context) error                                   { return nil }

func consumer(t *testing.T, f *fixture, g *protectedFixture) (*queue.Consumer, *brokerDouble) {
	t.Helper()
	schema, err := queue.NewSchema(queue.SchemaConfig{ID: "fixture", Version: "1", SchemaField: "schema", VersionField: "version", ReferenceField: "reference", ValidReference: func(s string) bool { return s == "opaque-job" }})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := schema.Encode(schema.Metadata("opaque-job"))
	if err != nil {
		t.Fatal(err)
	}
	b := &brokerDouble{d: queue.Delivery{ID: "1-0", Fields: fields}}
	p, err := queue.NewProtectedProcessor(queue.ProtectedConfig{PEP: g.p, Tool: func(context.Context, authorization.WorkerRequest) (authorization.Tool, error) { return g.db, nil }})
	if err != nil {
		t.Fatal(err)
	}
	c, err := queue.NewConsumer(queue.ConsumerConfig{Broker: b, Schema: schema, Processor: p, Store: &storeDouble{}, Retry: queue.RetryPolicy{MaxAttempts: 2, Backoff: func(uint32) time.Duration { return 0 }}, Audit: f.config.Audit, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return c, b
}

func TestQueueRecoveryUsesTransportIdentity(t *testing.T) {
	for _, name := range []string{"completion and duplicate", "wrong worker claim", "no transport claim", "spoofed fields", "rotation does not restore approval", "recovery fresh subject PDP", "refresh failure before claim"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			g := protected(f)
			c, b := consumer(t, f, g)
			id := "spiffe://fixture.test/worker-a"
			if name == "wrong worker claim" {
				id = "spiffe://fixture.test/worker-b"
			}
			s, err := f.connect(t, f.cert(t, id, nil))
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.WorkerContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if name == "no transport claim" {
				ctx = context.Background()
			}
			if name == "refresh failure before claim" {
				f.source.err = errors.New("refresh failed")
			}
			if name == "no transport claim" || name == "refresh failure before claim" {
				if _, err := c.Recover(ctx, 1, time.Second); err == nil || b.claims != 0 || b.acks != 0 || g.calls != 0 || g.db.txs != 0 {
					t.Fatal("claim without verified transport")
				}
				return
			}
			if name == "wrong worker claim" {
				_, _ = c.Recover(ctx, 1, time.Second)
				if b.claims != 1 || b.dlq != 1 || g.calls != 0 || g.db.runs != 0 {
					t.Fatal("claim replaced worker authorization")
				}
				return
			}
			if name == "spoofed fields" {
				b.d.Fields["actor"] = "worker-a"
				_, _ = c.Handle(ctx, b.d)
				if b.dlq != 1 || g.db.runs != 0 {
					t.Fatal("queue actor field accepted")
				}
				return
			}
			b.ackErr = errors.New("credential=redis-secret")
			_, _ = c.Handle(ctx, b.d)
			if g.db.runs != 1 || !g.db.a.Consumed {
				t.Fatal("initial operation failed")
			}
			b.ackErr = nil
			if name == "rotation does not restore approval" {
				renewed, err := f.connect(t, f.cert(t, id, nil))
				if err != nil {
					t.Fatal(err)
				}
				ctx, err = renewed.WorkerContext(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := g.p.ExecuteWorker(ctx, g.request, g.db); err == nil || g.db.runs != 1 {
					t.Fatal("new SVID reused consumed approval")
				}
			}
			if name == "recovery fresh subject PDP" {
				g.p.Policy = policyDouble(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					g.calls++
					return authorization.Decision{ActorAllowed: true}, nil
				})
			}
			before := g.calls
			_, _ = c.Recover(ctx, 1, time.Second)
			if g.db.runs != 1 || g.calls <= before {
				t.Fatal("recovery repeated operation or skipped fresh PDP")
			}
			if name == "recovery fresh subject PDP" {
				if b.dlq != 1 {
					t.Fatal("subject denial bypassed")
				}
			} else if b.acks != 2 || b.dlq != 0 {
				t.Fatal("ACK recovery failed")
			}
		})
	}
}
