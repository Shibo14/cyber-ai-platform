package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These repositories and objects are TEST FIXTURES, not a production approval
// schema, permission vocabulary, resource model or approval-issuance workflow.
type sqlApprovals struct{}

func (sqlApprovals) Load(ctx context.Context, tx tenantdb.TenantTx, id string) (Approval, error) {
	var a Approval
	err := tx.QueryRow(ctx, `SELECT id, tenant_id::text, subject_id, action, resource_id,
		input_fingerprint, resource_state, issued_at, expires_at, consumed
		FROM public.cyb13_test_approvals WHERE id = $1 FOR UPDATE`, id).Scan(
		&a.ID, &a.TenantID, &a.Subject, &a.Operation.Action, &a.Operation.ResourceID,
		&a.Operation.InputFingerprint, &a.ResourceState, &a.IssuedAt, &a.ExpiresAt, &a.Consumed)
	return a, err
}

func (sqlApprovals) Consume(ctx context.Context, tx tenantdb.TenantTx, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.cyb13_test_approvals SET consumed = true
		WHERE id = $1 AND consumed = false`, id)
	return tag.RowsAffected() == 1, err
}

type sqlTool struct {
	changeAfterRead bool
	failAfterWrite  bool
}

func (tool sqlTool) LockState(ctx context.Context, tx tenantdb.TenantTx, e Execution) (string, error) {
	var state string
	err := tx.QueryRow(ctx, `SELECT resource_state FROM public.cyb13_test_objects
		WHERE resource_id = $1 FOR UPDATE`, e.Operation.ResourceID).Scan(&state)
	if err == nil && tool.changeAfterRead {
		_, err = tx.Exec(ctx, `UPDATE public.cyb13_test_objects SET resource_state = 'v2' WHERE resource_id = $1`, e.Operation.ResourceID)
	}
	return state, err
}

func (tool sqlTool) ExecuteIfState(ctx context.Context, tx tenantdb.TenantTx, e Execution, expected string) error {
	// Fixed SQL and bind parameters, WITHIN the same CYB-12 RLS transaction.
	tag, err := tx.Exec(ctx, `UPDATE public.cyb13_test_objects SET executions = executions + 1
		WHERE resource_id = $1 AND resource_state = $2`, e.Operation.ResourceID, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrState
	}
	if tool.failAfterWrite {
		return errors.New("simulated transaction failure after write")
	}
	return nil
}

func TestPostgresProtectedExecution(t *testing.T) {
	adminURL := os.Getenv("CYB12_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set CYB12_TEST_DATABASE_URL to a bootstrapped disposable CYB-12 PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	// CYB-12 bootstrap is a prerequisite; no production grants/schema are changed.
	if _, err := admin.Exec(ctx, `CREATE ROLE cyb13_test_login LOGIN NOSUPERUSER NOCREATEDB
		NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'cyb13-local-test-only';
		GRANT cyber_runtime TO cyb13_test_login;
		CREATE TABLE public.cyb13_test_approvals (
			id text PRIMARY KEY, tenant_id uuid NOT NULL, subject_id text NOT NULL,
			action text NOT NULL, resource_id text NOT NULL, input_fingerprint text NOT NULL,
			resource_state text NOT NULL, issued_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL, consumed boolean NOT NULL DEFAULT false);
		CREATE TABLE public.cyb13_test_objects (
			tenant_id uuid NOT NULL, resource_id text PRIMARY KEY,
			resource_state text NOT NULL, executions integer NOT NULL DEFAULT 0);
		ALTER TABLE public.cyb13_test_approvals ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.cyb13_test_approvals FORCE ROW LEVEL SECURITY;
		CREATE POLICY approval_tenant ON public.cyb13_test_approvals TO cyber_runtime
			USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
			WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
		ALTER TABLE public.cyb13_test_objects ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.cyb13_test_objects FORCE ROW LEVEL SECURITY;
		CREATE POLICY object_tenant ON public.cyb13_test_objects TO cyber_runtime
			USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
			WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
		GRANT SELECT, UPDATE ON public.cyb13_test_approvals, public.cyb13_test_objects TO cyber_runtime`); err != nil {
		t.Fatalf("create isolated test fixtures (apply CYB-12 bootstrap first): %v", err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), `DROP TABLE public.cyb13_test_approvals, public.cyb13_test_objects;
			REVOKE cyber_runtime FROM cyb13_test_login; DROP ROLE cyb13_test_login`); err != nil {
			t.Errorf("clean up test fixtures: %v", err)
		}
	}()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("cyb13_test_login", "cyb13-local-test-only")
	db, err := tenantdb.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	seed := func(t *testing.T) *fixture {
		t.Helper()
		f := newFixture()
		f.p.DB, f.p.Approvals = db, sqlApprovals{}
		// Keep the fixture clock deterministic; timestamps are bind parameters.
		f.request.ApprovalID = t.Name()
		a := f.m.approval
		if _, err := admin.Exec(ctx, `DELETE FROM public.cyb13_test_approvals;
			DELETE FROM public.cyb13_test_objects`); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO public.cyb13_test_approvals
			(id, tenant_id, subject_id, action, resource_id, input_fingerprint, resource_state, issued_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, f.request.ApprovalID, string(a.TenantID), string(a.Subject),
			a.Operation.Action, a.Operation.ResourceID, a.Operation.InputFingerprint, a.ResourceState, a.IssuedAt, a.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO public.cyb13_test_objects
			(tenant_id, resource_id, resource_state) VALUES ($1,$2,$3)`, string(tenantA), a.Operation.ResourceID, a.ResourceState); err != nil {
			t.Fatal(err)
		}
		return f
	}
	check := func(t *testing.T, f *fixture, executions int, consumed bool) {
		t.Helper()
		var actualExecutions int
		var actualConsumed bool
		if err := admin.QueryRow(ctx, `SELECT executions FROM public.cyb13_test_objects WHERE resource_id = $1`, f.request.Operation.ResourceID).Scan(&actualExecutions); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT consumed FROM public.cyb13_test_approvals WHERE id = $1`, f.request.ApprovalID).Scan(&actualConsumed); err != nil {
			t.Fatal(err)
		}
		if actualExecutions != executions || actualConsumed != consumed {
			t.Fatalf("executions/consumption = %d/%v, want %d/%v", actualExecutions, actualConsumed, executions, consumed)
		}
	}
	t.Run("unchanged object and replay", func(t *testing.T) {
		f := seed(t)
		if err := f.p.Execute(f.ctx, f.request, sqlTool{}); err != nil {
			t.Fatal(err)
		}
		if err := f.p.Execute(f.ctx, f.request, sqlTool{}); !errors.Is(err, ErrDenied) {
			t.Fatalf("replay = %v", err)
		}
		check(t, f, 1, true)
	})
	t.Run("changed object since issuance", func(t *testing.T) {
		f := seed(t)
		if _, err := admin.Exec(ctx, `UPDATE public.cyb13_test_objects SET resource_state = 'v2'`); err != nil {
			t.Fatal(err)
		}
		if err := f.p.Execute(f.ctx, f.request, sqlTool{}); !errors.Is(err, ErrDenied) {
			t.Fatalf("changed object = %v", err)
		}
		check(t, f, 0, false)
	})
	t.Run("final compare and set", func(t *testing.T) {
		f := seed(t)
		if err := f.p.Execute(f.ctx, f.request, sqlTool{changeAfterRead: true}); !errors.Is(err, ErrState) {
			t.Fatalf("stale precondition = %v", err)
		}
		check(t, f, 0, false)
	})
	t.Run("write failure rolls back approval and object", func(t *testing.T) {
		f := seed(t)
		if err := f.p.Execute(f.ctx, f.request, sqlTool{failAfterWrite: true}); !errors.Is(err, ErrDependency) {
			t.Fatalf("failed tool = %v", err)
		}
		check(t, f, 0, false)
	})
	t.Run("RLS prevents another tenant using approval", func(t *testing.T) {
		f := seed(t)
		other := tenantidentity.WithAuthenticatedIdentity(f.ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "user-a"})
		if err := f.p.Execute(other, f.request, sqlTool{}); err == nil {
			t.Fatal("cross-tenant operation allowed")
		}
		check(t, f, 0, false)
	})
	t.Run("concurrent replay executes once", func(t *testing.T) {
		f := seed(t)
		// The fixture's policy recorder is not used concurrently.
		f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
			return Decision{ActorAllowed: true, SubjectAllowed: true}, nil
		})
		const callers = 8
		var workers sync.WaitGroup
		results := make(chan error, callers)
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			workers.Go(func() {
				<-start
				results <- f.p.Execute(f.ctx, f.request, sqlTool{})
			})
		}
		close(start)
		workers.Wait()
		close(results)
		allowed := 0
		for err := range results {
			if err == nil {
				allowed++
			} else if !errors.Is(err, ErrDenied) {
				t.Error(fmt.Errorf("unexpected replay failure: %w", err))
			}
		}
		if allowed != 1 {
			t.Fatalf("successful concurrent executions = %d, want 1", allowed)
		}
		check(t, f, 1, true)
	})
}
