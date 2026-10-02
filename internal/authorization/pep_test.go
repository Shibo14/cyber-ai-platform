package authorization

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

const tenantA tenantidentity.TenantID = "a0b1c2d3-e4f5-4678-9abc-def012345678"
const tenantB tenantidentity.TenantID = "b0b1c2d3-e4f5-4678-9abc-def012345678"

type policyFunc func(context.Context, Execution) (Decision, error)

func (f policyFunc) Evaluate(ctx context.Context, e Execution) (Decision, error) { return f(ctx, e) }

// memoryBoundary models a transaction: both approval consumption and tool state
// roll back on callback error. PostgreSQL integration below tests the real tx.
type memoryBoundary struct {
	mu           sync.Mutex
	approval     Approval
	state        string
	executions   int
	loadErr      error
	consumeErr   error
	stateErr     error
	executeErr   error
	consumeLost  bool
	afterLoad    func()
	afterState   func()
	afterConsume func()
}

func (m *memoryBoundary) WithTenantTx(ctx context.Context, fn func(tenantdb.TenantTx) error) error {
	if _, ok := tenantidentity.FromContext(ctx); !ok {
		return ErrDenied
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	beforeApproval, beforeState := m.approval, m.state
	err := fn(nil)
	if err != nil {
		m.approval, m.state = beforeApproval, beforeState
	}
	return err
}

func (m *memoryBoundary) Load(_ context.Context, _ tenantdb.TenantTx, id string) (Approval, error) {
	if m.loadErr != nil {
		return Approval{}, m.loadErr
	}
	if id != m.approval.ID {
		return Approval{}, errors.New("not found")
	}
	if m.afterLoad != nil {
		m.afterLoad()
	}
	return m.approval, nil
}

func (m *memoryBoundary) Consume(context.Context, tenantdb.TenantTx, string) (bool, error) {
	if m.consumeErr != nil {
		return false, m.consumeErr
	}
	if m.approval.Consumed || m.consumeLost {
		return false, nil
	}
	m.approval.Consumed = true
	if m.afterConsume != nil {
		m.afterConsume()
	}
	return true, nil
}

func (m *memoryBoundary) LockState(context.Context, tenantdb.TenantTx, Execution) (string, error) {
	state := m.state
	if m.afterState != nil {
		m.afterState()
	}
	return state, m.stateErr
}

func (m *memoryBoundary) ExecuteIfState(_ context.Context, _ tenantdb.TenantTx, _ Execution, expected string) error {
	if m.state != expected {
		return ErrState
	}
	if m.executeErr != nil {
		return m.executeErr
	}
	m.executions++
	m.state = "v2"
	return nil
}

type delegationStore struct {
	items   map[string]Delegation
	loadErr error
	saveErr error
}

func (s *delegationStore) Create(_ context.Context, d Delegation) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	if _, exists := s.items[d.ID]; exists {
		return errors.New("duplicate")
	}
	s.items[d.ID] = d
	return nil
}

func (s *delegationStore) Load(_ context.Context, id string) (Delegation, error) {
	if s.loadErr != nil {
		return Delegation{}, s.loadErr
	}
	d, ok := s.items[id]
	if !ok {
		return Delegation{}, errors.New("not found")
	}
	return d, nil
}

type fixture struct {
	p        *PEP
	m        *memoryBoundary
	store    *delegationStore
	ctx      context.Context
	request  Request
	now      time.Time
	log      bytes.Buffer
	policies []Execution
}

func newFixture() *fixture {
	f := &fixture{now: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	f.ctx = WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(),
		tenantidentity.Identity{TenantID: tenantA, PrincipalID: "user-a"}), "api")
	f.request = Request{Operation: Operation{Action: "protected.update", ResourceID: "object:1",
		InputFingerprint: "arguments-v1"}, CorrelationID: "job-1", ApprovalID: "approval-1"}
	f.m = &memoryBoundary{state: "v1", approval: Approval{ID: "approval-1", TenantID: tenantA,
		Subject: "user-a", Operation: f.request.Operation, ResourceState: "v1",
		IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}}
	f.store = &delegationStore{items: make(map[string]Delegation)}
	f.p = &PEP{DB: f.m, Approvals: f.m, Delegations: f.store,
		Now: func() time.Time { return f.now }, Audit: audit.New(&f.log,
			"event", "outcome", "tenant_id", "actor_id", "subject_id", "action", "resource_id", "correlation_id")}
	f.p.Policy = policyFunc(func(_ context.Context, e Execution) (Decision, error) {
		f.policies = append(f.policies, e)
		return Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	return f
}

func TestApprovalBindingAndFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fixture)
		want   error
	}{
		{"unchanged object", func(*fixture) {}, nil},
		{"changed object", func(f *fixture) { f.m.state = "v2" }, ErrDenied},
		{"changed action", func(f *fixture) { f.request.Operation.Action = "protected.delete" }, ErrDenied},
		{"changed resource", func(f *fixture) { f.request.Operation.ResourceID = "object:2" }, ErrDenied},
		{"changed arguments", func(f *fixture) { f.request.Operation.InputFingerprint = "arguments-v2" }, ErrDenied},
		{"changed tenant", func(f *fixture) { f.m.approval.TenantID = tenantB }, ErrDenied},
		{"changed principal", func(f *fixture) { f.m.approval.Subject = "user-b" }, ErrDenied},
		{"expiry boundary", func(f *fixture) { f.m.approval.ExpiresAt = f.now }, ErrDenied},
		{"future issuance", func(f *fixture) { f.m.approval.IssuedAt = f.now.Add(time.Second) }, ErrDenied},
		{"missing issuance", func(f *fixture) { f.m.approval.IssuedAt = time.Time{} }, ErrDenied},
		{"missing approval", func(f *fixture) { f.request.ApprovalID = "" }, ErrDenied},
		{"unknown approval", func(f *fixture) { f.request.ApprovalID = "unknown" }, ErrDependency},
		{"consumed approval", func(f *fixture) { f.m.approval.Consumed = true }, ErrDenied},
		{"approval load failure", func(f *fixture) { f.m.loadErr = errors.New("access_token=store-secret") }, ErrDependency},
		{"approval consumption failure", func(f *fixture) { f.m.consumeErr = errors.New("store failed") }, ErrDependency},
		{"atomic consumption lost", func(f *fixture) { f.m.consumeLost = true }, ErrDenied},
		{"state load failure", func(f *fixture) { f.m.stateErr = errors.New("failed") }, ErrDependency},
		{"empty state", func(f *fixture) { f.m.state = "" }, ErrDenied},
		{"PDP subject denial", func(f *fixture) {
			f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
				return Decision{ActorAllowed: true}, nil
			})
		}, ErrDenied},
		{"PDP actor denial", func(f *fixture) {
			f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
				return Decision{SubjectAllowed: true}, nil
			})
		}, ErrDenied},
		{"PDP outage", func(f *fixture) {
			f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
				return Decision{ActorAllowed: true, SubjectAllowed: true}, errors.New("password=pdp-secret")
			})
		}, ErrDependency},
		{"missing PDP", func(f *fixture) { f.p.Policy = nil }, ErrDependency},
		{"missing store", func(f *fixture) { f.p.Approvals = nil }, ErrDependency},
		{"missing transaction boundary", func(f *fixture) { f.p.DB = nil }, ErrDependency},
		{"missing audit boundary", func(f *fixture) { f.p.Audit = nil }, ErrDependency},
		{"missing trusted identity", func(f *fixture) { f.ctx = WithVerifiedActor(context.Background(), "api") }, ErrDenied},
		{"missing actor", func(f *fixture) {
			f.ctx = tenantidentity.WithAuthenticatedIdentity(context.Background(),
				tenantidentity.Identity{TenantID: tenantA, PrincipalID: "user-a"})
		}, ErrDenied},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture()
			test.change(f)
			err := f.p.Execute(f.ctx, f.request, f.m)
			if !errors.Is(err, test.want) {
				t.Fatalf("Execute() = %v, want %v", err, test.want)
			}
			wantExecutions := 0
			if test.want == nil {
				wantExecutions = 1
			}
			if f.m.executions != wantExecutions {
				t.Fatalf("tool executions = %d, want %d", f.m.executions, wantExecutions)
			}
			for _, secret := range []string{"store-secret", "pdp-secret"} {
				if strings.Contains(f.log.String(), secret) {
					t.Fatalf("raw dependency error leaked: %s", f.log.String())
				}
			}
		})
	}
}

func TestApprovalReplayAndFinalStatePrecondition(t *testing.T) {
	t.Run("one shot even if state returns to approved version", func(t *testing.T) {
		f := newFixture()
		if err := f.p.Execute(f.ctx, f.request, f.m); err != nil {
			t.Fatal(err)
		}
		f.m.state = "v1"
		if err := f.p.Execute(f.ctx, f.request, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 1 {
			t.Fatalf("replay = %v, executions = %d", err, f.m.executions)
		}
	})
	t.Run("change between check and mutation", func(t *testing.T) {
		f := newFixture()
		f.m.afterState = func() { f.m.state = "changed" }
		if err := f.p.Execute(f.ctx, f.request, f.m); !errors.Is(err, ErrState) {
			t.Fatalf("final precondition = %v", err)
		}
		if f.m.executions != 0 || f.m.approval.Consumed {
			t.Fatal("stale execution occurred or approval consumption did not roll back")
		}
	})
	t.Run("tool failure rolls back consumption", func(t *testing.T) {
		f := newFixture()
		f.m.executeErr = errors.New("tool failed")
		if err := f.p.Execute(f.ctx, f.request, f.m); !errors.Is(err, ErrDependency) || f.m.approval.Consumed {
			t.Fatalf("failed execution = %v, consumed = %v", err, f.m.approval.Consumed)
		}
	})
}

func TestValidityAfterBlockingDependencies(t *testing.T) {
	for _, stage := range []string{"load", "state", "consume"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture()
			expire := func() { f.now = f.now.Add(2 * time.Minute) }
			switch stage {
			case "load":
				f.m.afterLoad = expire
			case "state":
				f.m.afterState = expire
			case "consume":
				f.m.afterConsume = expire
			}
			if err := f.p.Execute(f.ctx, f.request, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 0 {
				t.Fatalf("expired at %s: %v, executions = %d", stage, err, f.m.executions)
			}
		})
	}
}

func (f *fixture) job(t *testing.T) (context.Context, WorkerRequest) {
	t.Helper()
	id, err := f.p.Delegate(f.ctx, f.request, "worker-a", f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	f.policies = nil
	return WithVerifiedWorker(context.Background(), "worker-a"), WorkerRequest{
		DelegationID: id, Operation: f.request.Operation, CorrelationID: f.request.CorrelationID,
	}
}

func TestWorkerDelegation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fixture, *context.Context, *WorkerRequest)
		want   error
	}{
		{"permitted exact job", func(*fixture, *context.Context, *WorkerRequest) {}, nil},
		{"different action", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.Operation.Action = "delete" }, ErrDenied},
		{"different resource", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.Operation.ResourceID = "object:2" }, ErrDenied},
		{"different arguments", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.Operation.InputFingerprint = "tampered" }, ErrDenied},
		{"different correlation", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.CorrelationID = "job-2" }, ErrDenied},
		{"different tenant", func(_ *fixture, ctx *context.Context, _ *WorkerRequest) {
			*ctx = tenantidentity.WithAuthenticatedIdentity(*ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "user-a"})
		}, ErrDenied},
		{"another user's authority", func(_ *fixture, ctx *context.Context, _ *WorkerRequest) {
			*ctx = tenantidentity.WithAuthenticatedIdentity(*ctx, tenantidentity.Identity{TenantID: tenantA, PrincipalID: "user-b"})
		}, ErrDenied},
		{"different workload", func(_ *fixture, ctx *context.Context, _ *WorkerRequest) { *ctx = WithVerifiedWorker(*ctx, "worker-b") }, ErrDenied},
		{"unverified workload", func(_ *fixture, ctx *context.Context, _ *WorkerRequest) { *ctx = context.Background() }, ErrDenied},
		{"missing delegation", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.DelegationID = "" }, ErrDenied},
		{"tampered reference", func(_ *fixture, _ *context.Context, r *WorkerRequest) { r.DelegationID = "injected" }, ErrDependency},
		{"tampered returned record ID", func(f *fixture, _ *context.Context, r *WorkerRequest) {
			d := f.store.items[r.DelegationID]
			d.ID = "wrong"
			f.store.items[r.DelegationID] = d
		}, ErrDenied},
		{"tampered subject binding", func(f *fixture, _ *context.Context, r *WorkerRequest) {
			d := f.store.items[r.DelegationID]
			d.Execution.Subject = "user-b"
			f.store.items[r.DelegationID] = d
		}, ErrDenied},
		{"tampered tenant binding", func(f *fixture, _ *context.Context, r *WorkerRequest) {
			d := f.store.items[r.DelegationID]
			d.Execution.TenantID = tenantB
			f.store.items[r.DelegationID] = d
		}, ErrDenied},
		{"expired delegation", func(f *fixture, _ *context.Context, r *WorkerRequest) {
			d := f.store.items[r.DelegationID]
			d.ExpiresAt = f.now
			f.store.items[r.DelegationID] = d
		}, ErrDenied},
		{"store outage", func(f *fixture, _ *context.Context, _ *WorkerRequest) { f.store.loadErr = errors.New("failed") }, ErrDependency},
		{"worker broader than subject", func(f *fixture, _ *context.Context, _ *WorkerRequest) {
			f.p.Policy = policyFunc(func(_ context.Context, e Execution) (Decision, error) {
				if e.Actor != "worker-a" || e.Subject != "user-a" || e.TenantID != tenantA {
					t.Error("PDP did not receive both identities and tenant")
				}
				return Decision{ActorAllowed: true, SubjectAllowed: false}, nil
			})
		}, ErrDenied},
		{"execution PDP outage", func(f *fixture, _ *context.Context, _ *WorkerRequest) {
			f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{}, errors.New("outage") })
		}, ErrDependency},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture()
			ctx, request := f.job(t)
			test.change(f, &ctx, &request)
			err := f.p.ExecuteWorker(ctx, request, f.m)
			if !errors.Is(err, test.want) {
				t.Fatalf("ExecuteWorker() = %v, want %v", err, test.want)
			}
			wantExecutions := 0
			if test.want == nil {
				wantExecutions = 1
				if len(f.policies) != 1 || f.policies[0].Subject != "user-a" || f.policies[0].Actor != "worker-a" {
					t.Fatal("worker bypassed execution PDP or collapsed actor and subject")
				}
			}
			if f.m.executions != wantExecutions {
				t.Fatalf("executions = %d", f.m.executions)
			}
		})
	}
}

func TestDelegationValidityAtFinalExecutionBoundary(t *testing.T) {
	for _, stage := range []string{"load", "state", "consume"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture()
			ctx, request := f.job(t)
			f.m.approval.ExpiresAt = f.now.Add(5 * time.Minute)
			expireDelegation := func() { f.now = f.now.Add(2 * time.Minute) }
			switch stage {
			case "load":
				f.m.afterLoad = expireDelegation
			case "state":
				f.m.afterState = expireDelegation
			case "consume":
				f.m.afterConsume = expireDelegation
			}
			if err := f.p.ExecuteWorker(ctx, request, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 0 || f.m.approval.Consumed {
				t.Fatalf("delegation expired during %s: %v, executions = %d, consumed = %v", stage, err, f.m.executions, f.m.approval.Consumed)
			}
		})
	}
}

func TestWorkerCannotDowngradeToDirectExecution(t *testing.T) {
	f := newFixture()
	worker := WithVerifiedWorker(f.ctx, "worker-a")
	if err := f.p.Execute(worker, f.request, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 0 {
		t.Fatalf("worker direct execution = %v", err)
	}
}

func TestClientAuthorityInjectionIgnored(t *testing.T) {
	f := newFixture()
	r := httptest.NewRequest("POST", "/protected?tenant_id="+string(tenantB),
		strings.NewReader(`{"tenant_id":"injected","actor":"root-worker","subject":"admin","permissions":["all"]}`))
	r.Header.Set("X-Tenant-ID", string(tenantB))
	r.Header.Set("X-Subject-ID", "admin")
	r.Header.Set("X-Actor-ID", "root-worker")
	// The trusted middleware context is the only source of authority.
	r = r.WithContext(f.ctx)
	if err := f.p.Execute(r.Context(), f.request, f.m); err != nil {
		t.Fatal(err)
	}
	e := f.policies[0]
	if e.TenantID != tenantA || e.Subject != "user-a" || e.Actor != "api" {
		t.Fatalf("client authority was used: %+v", e)
	}
	f = newFixture()
	if err := f.p.Execute(context.Background(), f.request, f.m); !errors.Is(err, ErrDenied) {
		t.Fatalf("client fields established authority: %v", err)
	}
}

func TestDelegationAdmissionFailsClosed(t *testing.T) {
	for _, failure := range []string{"subject-denied", "worker-denied", "storage-error", "expired"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture()
			expires := f.now.Add(time.Minute)
			switch failure {
			case "subject-denied":
				f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{ActorAllowed: true}, nil })
			case "worker-denied":
				f.p.Policy = policyFunc(func(_ context.Context, e Execution) (Decision, error) {
					return Decision{ActorAllowed: e.Actor == "api", SubjectAllowed: true}, nil
				})
			case "storage-error":
				f.store.saveErr = errors.New("storage failed")
			case "expired":
				expires = f.now
			}
			if id, err := f.p.Delegate(f.ctx, f.request, "worker-a", expires); err == nil || id != "" || len(f.store.items) != 0 {
				t.Fatalf("unauthorized job created: %q, %v", id, err)
			}
		})
	}
}
