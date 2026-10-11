package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
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
	t.Run("ExecutionAdmissionOutsideTransactionAndLocks", func(t *testing.T) {
		for _, mode := range []string{"success", "state changed", "approval consumed", "approval expired", "PDP revoked", "admission denied", "admission timeout", "execution rollback"} {
			t.Run(mode, func(t *testing.T) {
				f := seed(t)
				var revoked atomic.Bool
				f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
					return Decision{ActorAllowed: true, SubjectAllowed: !revoked.Load()}, nil
				})
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				gateCalls := 0
				bound, err := BindAdmission(f.p, admissionFunc(func(c context.Context, _ Execution, stage AdmissionStage) error {
					gateCalls++
					if stage != ExecutionStage {
						return ErrDenied
					}
					close(entered)
					select {
					case <-release:
					case <-c.Done():
						return c.Err()
					}
					if mode == "admission denied" {
						return ErrDenied
					}
					if mode == "admission timeout" {
						return context.DeadlineExceeded
					}
					return nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- bound.Execute(f.ctx, f.request, sqlTool{failAfterWrite: mode == "execution rollback"}) }()
				// Cleanup always joins the goroutine before fixtures are removed.
				joined := false
				defer func() {
					unblock()
					if !joined {
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("execution did not terminate")
						}
					}
				}()
				select {
				case <-entered:
				case err := <-done:
					joined = true
					t.Fatalf("admission never reached: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("admission did not start")
				}
				probeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				var active int
				if err := admin.QueryRow(probeCtx, `SELECT count(*) FROM pg_stat_activity
					WHERE usename = 'cyb13_test_login' AND xact_start IS NOT NULL`).Scan(&active); err != nil {
					t.Fatal(err)
				}
				if active != 0 {
					t.Fatalf("slow limiter holds %d PostgreSQL transactions", active)
				}
				// Independent real connection obtains BOTH rows without waiting
				// while admission is blocked. FOR UPDATE NOWAIT fails on any leak.
				probe, err := admin.Begin(probeCtx)
				if err != nil {
					t.Fatal(err)
				}
				defer probe.Rollback(context.Background())
				var id string
				if err := probe.QueryRow(probeCtx, `SELECT id FROM public.cyb13_test_approvals WHERE id=$1 FOR UPDATE NOWAIT`, f.request.ApprovalID).Scan(&id); err != nil {
					t.Fatalf("approval row locked during admission: %v", err)
				}
				if err := probe.QueryRow(probeCtx, `SELECT resource_id FROM public.cyb13_test_objects WHERE resource_id=$1 FOR UPDATE NOWAIT`, f.request.Operation.ResourceID).Scan(&id); err != nil {
					t.Fatalf("object row locked during admission: %v", err)
				}
				switch mode {
				case "state changed":
					_, err = probe.Exec(probeCtx, `UPDATE public.cyb13_test_objects SET resource_state='v2' WHERE resource_id=$1`, f.request.Operation.ResourceID)
				case "approval consumed":
					_, err = probe.Exec(probeCtx, `UPDATE public.cyb13_test_approvals SET consumed=true WHERE id=$1`, f.request.ApprovalID)
				case "approval expired":
					f.now = f.now.Add(time.Hour)
				case "PDP revoked":
					revoked.Store(true)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := probe.Commit(probeCtx); err != nil {
					t.Fatal(err)
				}
				unblock()
				select {
				case err = <-done:
					joined = true
				case <-time.After(5 * time.Second):
					t.Fatal("final execution stalled")
				}
				if gateCalls != 1 {
					t.Fatalf("admission calls = %d", gateCalls)
				}
				if mode == "success" {
					if err != nil {
						t.Fatal(err)
					}
					check(t, f, 1, true)
				} else {
					if err == nil {
						t.Fatal("stale/denied admission executed")
					}
					check(t, f, 0, mode == "approval consumed")
				}
			})
		}
	})
	t.Run("ConcurrentAdmittedReplayConsumesOnce", func(t *testing.T) {
		f := seed(t)
		f.p.Policy = policyFunc(func(context.Context, Execution) (Decision, error) {
			return Decision{ActorAllowed: true, SubjectAllowed: true}, nil
		})
		const count = 8
		var arrivals atomic.Int32
		release := make(chan struct{})
		bound, err := BindAdmission(f.p, admissionFunc(func(c context.Context, _ Execution, _ AdmissionStage) error {
			if arrivals.Add(1) == count {
				close(release)
			}
			select {
			case <-release:
				return nil
			case <-c.Done():
				return c.Err()
			}
		}))
		if err != nil {
			t.Fatal(err)
		}
		c, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		results := make(chan error, count)
		for i := 0; i < count; i++ {
			go func() { results <- bound.Execute(c, f.request, sqlTool{}) }()
		}
		allowed := 0
		for i := 0; i < count; i++ {
			err := <-results
			if err == nil {
				allowed++
			} else if !errors.Is(err, ErrDenied) {
				t.Error(err)
			}
		}
		if allowed != 1 || arrivals.Load() != count {
			t.Fatalf("allowed=%d admissions=%d", allowed, arrivals.Load())
		}
		check(t, f, 1, true)
	})
}
