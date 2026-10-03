package queue

// These tables, grants and credentials are disposable integration fixtures.
// They are not a production job/idempotency/approval schema or outbox decision.
import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type protectedSQLApprovals struct{}

func (protectedSQLApprovals) Load(ctx context.Context, tx tenantdb.TenantTx, id string) (authorization.Approval, error) {
	var a authorization.Approval
	err := tx.QueryRow(ctx, `SELECT id,tenant_id::text,subject_id,action,resource_id,input_fingerprint,resource_state,issued_at,expires_at,consumed
	FROM public.cyb15_test_approvals WHERE id=$1 FOR UPDATE`, id).Scan(&a.ID, &a.TenantID, &a.Subject, &a.Operation.Action, &a.Operation.ResourceID, &a.Operation.InputFingerprint, &a.ResourceState, &a.IssuedAt, &a.ExpiresAt, &a.Consumed)
	return a, err
}
func (protectedSQLApprovals) Consume(ctx context.Context, tx tenantdb.TenantTx, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.cyb15_test_approvals SET consumed=true WHERE id=$1 AND consumed=false`, id)
	return tag.RowsAffected() == 1, err
}

type protectedSQLTool struct{ fail bool }

func (protectedSQLTool) LockState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (string, error) {
	var state string
	err := tx.QueryRow(ctx, `SELECT resource_state FROM public.cyb15_test_objects WHERE resource_id=$1 FOR UPDATE`, e.Operation.ResourceID).Scan(&state)
	return state, err
}
func (tool protectedSQLTool) ExecuteIfState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string) error {
	tag, err := tx.Exec(ctx, `UPDATE public.cyb15_test_objects SET executions=executions+1 WHERE resource_id=$1 AND resource_state=$2`, e.Operation.ResourceID, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return authorization.ErrState
	}
	if tool.fail {
		return errors.New("fixture storage credential=never-log")
	}
	return nil
}

func TestPostgresQueueProtectedWorkerBoundary(t *testing.T) {
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
	_, err = admin.Exec(ctx, `CREATE ROLE cyb15_test_login LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD 'cyb15-local-test-only';
	GRANT cyber_runtime TO cyb15_test_login;
	CREATE TABLE public.cyb15_test_objects(tenant_id uuid NOT NULL,resource_id text PRIMARY KEY,resource_state text NOT NULL,executions integer NOT NULL DEFAULT 0);
	CREATE TABLE public.cyb15_test_approvals(id text PRIMARY KEY,tenant_id uuid NOT NULL,subject_id text NOT NULL,action text NOT NULL,resource_id text NOT NULL,input_fingerprint text NOT NULL,resource_state text NOT NULL,issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false);
	ALTER TABLE public.cyb15_test_objects ENABLE ROW LEVEL SECURITY; ALTER TABLE public.cyb15_test_objects FORCE ROW LEVEL SECURITY;
	ALTER TABLE public.cyb15_test_approvals ENABLE ROW LEVEL SECURITY; ALTER TABLE public.cyb15_test_approvals FORCE ROW LEVEL SECURITY;
	CREATE POLICY object_tenant ON public.cyb15_test_objects TO cyber_runtime
	USING(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
	CREATE POLICY approval_tenant ON public.cyb15_test_approvals TO cyber_runtime
	USING(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
	GRANT SELECT,UPDATE ON public.cyb15_test_objects,public.cyb15_test_approvals TO cyber_runtime`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err := admin.Exec(context.Background(), `DROP TABLE public.cyb15_test_objects,public.cyb15_test_approvals;REVOKE cyber_runtime FROM cyb15_test_login;DROP ROLE cyb15_test_login`)
		if err != nil {
			t.Error(err)
		}
	}()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("cyb15_test_login", "cyb15-local-test-only")
	db, err := tenantdb.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"same tenant", "cross-tenant object reference", "cross-tenant approval reference", "wrong claimed worker", "unverified worker", "write rollback", "committed operation retry", "committed ACK failure"} {
		t.Run(name, func(t *testing.T) {
			f := newProtectedFixture(t)
			f.pep.DB = db
			f.pep.Approvals = protectedSQLApprovals{}
			if _, err := admin.Exec(ctx, `DELETE FROM public.cyb15_test_objects;DELETE FROM public.cyb15_test_approvals`); err != nil {
				t.Fatal(err)
			}
			objectTenant := protectedTenantA
			approvalTenant := protectedTenantA
			if name == "cross-tenant object reference" {
				objectTenant = protectedTenantB
			}
			if name == "cross-tenant approval reference" {
				approvalTenant = protectedTenantB
			}
			a := f.boundary.approval
			if _, err := admin.Exec(ctx, `INSERT INTO public.cyb15_test_approvals(id,tenant_id,subject_id,action,resource_id,input_fingerprint,resource_state,issued_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, a.ID, string(approvalTenant), string(a.Subject), a.Operation.Action, a.Operation.ResourceID, a.Operation.InputFingerprint, a.ResourceState, a.IssuedAt, a.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `INSERT INTO public.cyb15_test_objects(tenant_id,resource_id,resource_state) VALUES($1,$2,$3)`, string(objectTenant), a.Operation.ResourceID, a.ResourceState); err != nil {
				t.Fatal(err)
			}
			m := f.metadata(t)
			tool := protectedSQLTool{fail: name == "write rollback"}
			processor, err := NewProtectedProcessor(ProtectedConfig{PEP: f.pep, Tool: func(context.Context, authorization.WorkerRequest) (authorization.Tool, error) { return tool, nil }})
			if err != nil {
				t.Fatal(err)
			}
			worker := authorization.WithVerifiedWorker(ctx, "fixture-worker")
			if name == "wrong claimed worker" {
				worker = authorization.WithVerifiedWorker(ctx, "other-worker")
			}
			if name == "unverified worker" {
				worker = ctx
			}
			if name == "committed ACK failure" {
				fields, err := f.schema.Encode(m)
				if err != nil {
					t.Fatal(err)
				}
				broker := &protectedBroker{fields: fields, ackErr: errors.New("Redis ACK outage")}
				consumer, err := NewConsumer(ConsumerConfig{Broker: broker, Schema: f.schema, Processor: processor, Store: &protectedTransportStore{}, Retry: RetryPolicy{MaxAttempts: 2, Backoff: func(uint32) time.Duration { return 0 }}, Audit: f.pep.Audit})
				if err != nil {
					t.Fatal(err)
				}
				delivery := Delivery{ID: "1-0", Fields: fields}
				if _, err := consumer.Handle(worker, delivery); !errors.Is(err, ErrACK) {
					t.Fatalf("committed ACK failure: %v", err)
				}
				broker.ackErr = nil
				result, recoveryErr := consumer.Handle(worker, delivery)
				if recoveryErr != nil || result.Outcome != Acknowledged {
					t.Fatalf("committed ACK recovery: %+v,%v", result, recoveryErr)
				}
				err = recoveryErr
			} else {
				err = processor.Process(worker, m)
			}
			wantSuccess := name == "same tenant" || name == "committed operation retry" || name == "committed ACK failure"
			if wantSuccess && err != nil {
				t.Fatalf("worker process: %v", err)
			}
			if !wantSuccess && err == nil {
				t.Fatal("invalid operation succeeded")
			}
			if name == "committed operation retry" {
				// An ACK outage does not undo PostgreSQL commit. Without approved
				// business reconciliation, the old approval must still deny reuse.
				if err := processor.Process(worker, m); Classify(err) != (Classification{Permanent, Denied}) {
					t.Fatalf("committed approval reused on retry: %v", err)
				}
			}
			var executions int
			var consumed bool
			if err := admin.QueryRow(ctx, `SELECT executions FROM public.cyb15_test_objects`).Scan(&executions); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT consumed FROM public.cyb15_test_approvals`).Scan(&consumed); err != nil {
				t.Fatal(err)
			}
			wantExecutions := 0
			if wantSuccess {
				wantExecutions = 1
			}
			if executions != wantExecutions || consumed != wantSuccess {
				t.Fatalf("executions/consumption %d/%v, want %d/%v", executions, consumed, wantExecutions, wantSuccess)
			}
			// Cross-tenant existence cannot become visible through a pooled tx.
			other := tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: protectedTenantB, PrincipalID: "fixture-user"})
			if objectTenant == protectedTenantA {
				if err := db.WithTenantTx(other, func(tx tenantdb.TenantTx) error {
					var count int
					err := tx.QueryRow(other, `SELECT count(*) FROM public.cyb15_test_objects`).Scan(&count)
					if err == nil && count != 0 {
						t.Fatal("RLS leaked other tenant object")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
