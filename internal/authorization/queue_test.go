package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"cyber-ai-platform/internal/tenantidentity"
)

func TestQueueResolveWorkerIsFreshNonConsumingPreflight(t *testing.T) {
	f := newFixture()
	ctx, request := f.job(t)
	got, err := f.p.ResolveWorker(ctx, request.DelegationID)
	if err != nil || got != request {
		t.Fatalf("ResolveWorker = %+v, %v", got, err)
	}
	if f.m.approval.Consumed || f.m.executions != 0 || len(f.policies) != 1 {
		t.Fatal("preflight consumed approval, executed a tool or skipped PDP")
	}
	f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
		return Decision{ActorAllowed: true}, nil
	})
	if err := f.p.ExecuteWorker(ctx, got, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 0 {
		t.Fatal("cached queue preflight replaced fresh execution authorization")
	}
}

func TestQueueResolveWorkerDenials(t *testing.T) {
	for _, name := range []string{"unverified", "nonworker", "wrong worker", "wrong tenant", "wrong subject", "expired", "bad record ID", "subject denied", "actor denied", "dependency"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			ctx, request := f.job(t)
			want := ErrDenied
			switch name {
			case "unverified":
				ctx = context.Background()
			case "nonworker":
				ctx = WithVerifiedActor(context.Background(), "worker-a")
			case "wrong worker":
				ctx = WithVerifiedWorker(context.Background(), "worker-b")
			case "wrong tenant":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "user-a"})
			case "wrong subject":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantA, PrincipalID: "user-b"})
			case "expired":
				f.now = f.now.Add(2 * time.Minute)
			case "bad record ID":
				d := f.store.items[request.DelegationID]
				d.ID = "other"
				f.store.items[request.DelegationID] = d
			case "subject denied":
				f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{ActorAllowed: true}, nil })
			case "actor denied":
				f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) { return Decision{SubjectAllowed: true}, nil })
			case "dependency":
				f.store.loadErr = errors.New("credential=do-not-expose")
				want = ErrDependency
			}
			got, err := f.p.ResolveWorker(ctx, request.DelegationID)
			if !errors.Is(err, want) || got != (WorkerRequest{}) || f.m.approval.Consumed || f.m.executions != 0 {
				t.Fatalf("ResolveWorker = %+v, %v", got, err)
			}
		})
	}
}

func TestQueuePreflightCannotReuseConsumedApproval(t *testing.T) {
	f := newFixture()
	ctx, request := f.job(t)
	if err := f.p.ExecuteWorker(ctx, request, f.m); err != nil {
		t.Fatal(err)
	}
	f.m.state = "v1"
	resolved, err := f.p.ResolveWorker(ctx, request.DelegationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.ExecuteWorker(ctx, resolved, f.m); !errors.Is(err, ErrDenied) || f.m.executions != 1 {
		t.Fatalf("retry reused approval: %v, executions %d", err, f.m.executions)
	}
}

func TestQueueWorkerEntryPointAndSlowPDPExpiry(t *testing.T) {
	f := newFixture()
	ctx, request := f.job(t)
	for _, untrusted := range []context.Context{context.Background(), WithVerifiedActor(context.Background(), "worker-a"), WithVerifiedWorker(context.Background(), "")} {
		if err := f.p.VerifyWorker(untrusted); !errors.Is(err, ErrDenied) {
			t.Fatalf("unverified worker accepted: %v", err)
		}
	}
	if err := f.p.VerifyWorker(ctx); err != nil {
		t.Fatal(err)
	}
	f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
		f.now = f.now.Add(2 * time.Minute)
		return Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	if _, err := f.p.ResolveWorker(ctx, request.DelegationID); !errors.Is(err, ErrDenied) {
		t.Fatalf("slow PDP authorized expired delegation: %v", err)
	}
}
