package authorization

import (
	"context"
	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/tenantdb"
	"errors"
	"strings"
	"testing"
	"time"
)

type admissionFunc func(context.Context, Execution, AdmissionStage) error

func (f admissionFunc) Admit(c context.Context, e Execution, s AdmissionStage) error {
	return f(c, e, s)
}

type admissionBoundary struct {
	base   TenantBoundary
	active bool
	calls  int
}

func (b *admissionBoundary) WithTenantTx(c context.Context, f func(tenantdb.TenantTx) error) error {
	b.active = true
	b.calls++
	defer func() { b.active = false }()
	return b.base.WithTenantTx(c, f)
}

func TestExecutionAdmissionReleasesTransaction(t *testing.T) {
	for _, mode := range []string{"success", "denied", "timeout", "canceled", "preflight denied"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			b := &admissionBoundary{base: f.m}
			f.p.DB = b
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			calls := 0
			bound, err := BindAdmission(f.p, admissionFunc(func(context.Context, Execution, AdmissionStage) error {
				calls++
				if b.active || b.calls != 1 || f.m.approval.Consumed {
					t.Fatal("admission inside transaction/after consumption")
				}
				switch mode {
				case "denied":
					return ErrDenied
				case "timeout":
					return context.DeadlineExceeded
				case "canceled":
					cancel()
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "preflight denied" {
				f.m.approval.Consumed = true
			}
			err = bound.Execute(ctx, f.request, f.m)
			if mode == "success" {
				if err != nil || b.calls != 2 || f.m.executions != 1 {
					t.Fatal(err)
				}
			} else {
				if err == nil || b.calls != 1 || f.m.executions != 0 {
					t.Fatal("denied admission reached final transaction")
				}
				if mode != "preflight denied" && f.m.approval.Consumed {
					t.Fatal("failed admission consumed approval")
				}
			}
			if mode == "preflight denied" && calls != 0 {
				t.Fatal("invalid preflight charged")
			}
		})
	}
}

func TestExecutionAdmissionReloadsWorkerDelegation(t *testing.T) {
	for _, mode := range []string{"deleted", "worker changed", "tenant changed", "approval changed", "expiry changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			id, err := f.p.Delegate(f.ctx, f.request, "worker-a", f.now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := BindAdmission(f.p, admissionFunc(func(context.Context, Execution, AdmissionStage) error {
				d := f.store.items[id]
				switch mode {
				case "deleted":
					delete(f.store.items, id)
					return nil
				case "worker changed":
					d.Execution.Actor = "worker-b"
				case "tenant changed":
					d.Execution.TenantID = tenantB
				case "approval changed":
					d.ApprovalID = "other"
				case "expiry changed":
					d.ExpiresAt = d.ExpiresAt.Add(time.Minute)
				}
				f.store.items[id] = d
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithVerifiedWorker(context.Background(), "worker-a")
			err = bound.ExecuteWorker(ctx, WorkerRequest{DelegationID: id, Operation: f.request.Operation, CorrelationID: f.request.CorrelationID}, f.m)
			if err == nil || f.m.executions != 0 || f.m.approval.Consumed {
				t.Fatal("changed authoritative delegation accepted after admission")
			}
		})
	}
}
func TestBoundAdmissionPreservesPEP(t *testing.T) {
	for _, mode := range []string{"valid", "denied admission", "slow admission", "PDP changed", "approval replay", "PDP denied before admission"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			calls := 0
			gate := admissionFunc(func(context.Context, Execution, AdmissionStage) error {
				calls++
				switch mode {
				case "denied admission":
					return errors.New("private backend")
				case "slow admission":
					f.now = f.now.Add(time.Hour)
				case "PDP changed":
					f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{}, nil })
				}
				return nil
			})
			var err error
			f.p, err = BindAdmission(f.p, gate)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "PDP denied before admission" {
				f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{}, nil })
			}
			err = f.p.Execute(f.ctx, f.request, f.m)
			if mode == "valid" || mode == "approval replay" {
				if err != nil || f.m.executions != 1 || !f.m.approval.Consumed {
					t.Fatal(err)
				}
				if mode == "approval replay" {
					if f.p.Execute(f.ctx, f.request, f.m) == nil || calls != 1 || f.m.executions != 1 {
						t.Fatal("replay")
					}
				}
			} else if err == nil || f.m.executions != 0 || f.m.approval.Consumed {
				t.Fatal("gate bypass")
			}
			if mode == "PDP denied before admission" && calls != 0 {
				t.Fatal("charged before authorization")
			}
		})
	}
	if _, err := BindAdmission(newFixture().p, nil); err == nil {
		t.Fatal("missing gate")
	}
}

type commitAuditFailure struct{ saved string }

func (w *commitAuditFailure) Write(p []byte) (int, error) {
	w.saved += string(p)
	return len(p), errors.New("secret sink")
}
func TestCommittedOperationAuditFailureKeepsApprovalConsumed(t *testing.T) {
	f := newFixture()
	w := &commitAuditFailure{}
	f.p.Audit = audit.New(w, "event", "outcome")
	if err := f.p.Execute(f.ctx, f.request, f.m); err != ErrDependency {
		t.Fatal(err)
	}
	if f.m.executions != 1 || !f.m.approval.Consumed {
		t.Fatal("audit failure pretended rollback")
	}
	if !strings.Contains(w.saved, `"outcome":"allowed"`) {
		t.Fatal("actual committed execution not recorded")
	}
	if f.p.Execute(f.ctx, f.request, f.m) == nil || f.m.executions != 1 {
		t.Fatal("audit failure restored approval")
	}
}
