package encryption

// This schema, JSON persistence, grants and credential are disposable fixtures,
// not a production data classification, envelope format or storage decision.
import (
	"bytes"
	"context"
	"encoding/json"
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

type postgresBoundary struct {
	db   *tenantdb.DB
	inTx bool
}

func (b *postgresBoundary) WithTenantTx(ctx context.Context, fn func(tenantdb.TenantTx) error) error {
	return b.db.WithTenantTx(ctx, func(tx tenantdb.TenantTx) error { b.inTx = true; defer func() { b.inTx = false }(); return fn(tx) })
}

type postgresApprovals struct{}

func (postgresApprovals) Load(ctx context.Context, tx tenantdb.TenantTx, id string) (authorization.Approval, error) {
	var a authorization.Approval
	err := tx.QueryRow(ctx, `SELECT id,tenant_id::text,subject_id,action,resource_id,input_fingerprint,resource_state,issued_at,expires_at,consumed
		FROM public.cyb14_test_approvals WHERE id=$1 FOR UPDATE`, id).Scan(&a.ID, &a.TenantID, &a.Subject, &a.Operation.Action, &a.Operation.ResourceID, &a.Operation.InputFingerprint, &a.ResourceState, &a.IssuedAt, &a.ExpiresAt, &a.Consumed)
	return a, err
}
func (postgresApprovals) Consume(ctx context.Context, tx tenantdb.TenantTx, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.cyb14_test_approvals SET consumed=true WHERE id=$1 AND consumed=false`, id)
	return tag.RowsAffected() == 1, err
}

type postgresStorage struct{ failWrite bool }

func (*postgresStorage) Operation(e authorization.Execution, in Inputs) (authorization.Operation, error) {
	return fixtureOperation(e, in), nil
}
func (*postgresStorage) LockState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (string, error) {
	var state string
	err := tx.QueryRow(ctx, `SELECT resource_state FROM public.cyb14_test_objects WHERE resource_id=$1 FOR UPDATE`, e.Operation.ResourceID).Scan(&state)
	return state, err
}
func (*postgresStorage) Load(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (Envelope, error) {
	var data []byte
	err := tx.QueryRow(ctx, `SELECT envelope FROM public.cyb14_test_objects WHERE resource_id=$1`, e.Operation.ResourceID).Scan(&data)
	if err != nil {
		return Envelope{}, err
	}
	var envelope Envelope
	err = json.Unmarshal(data, &envelope)
	return envelope, err
}
func (s *postgresStorage) StoreIfState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string, envelope Envelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.cyb14_test_objects SET envelope=$1 WHERE resource_id=$2 AND resource_state=$3`, data, e.Operation.ResourceID, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return authorization.ErrState
	}
	if s.failWrite {
		return errors.New("test rollback after encrypted write")
	}
	return nil
}
func (*postgresStorage) CheckState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string) error {
	var matches bool
	err := tx.QueryRow(ctx, `SELECT resource_state=$2 FROM public.cyb14_test_objects WHERE resource_id=$1 FOR UPDATE`, e.Operation.ResourceID, expected).Scan(&matches)
	if err != nil {
		return err
	}
	if !matches {
		return authorization.ErrState
	}
	return nil
}

func TestPostgresEnvelopeBoundary(t *testing.T) {
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
	_, err = admin.Exec(ctx, `CREATE ROLE cyb14_test_login LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD 'cyb14-local-test-only';
		GRANT cyber_runtime TO cyb14_test_login;
		CREATE TABLE public.cyb14_test_objects(tenant_id uuid NOT NULL,resource_id text PRIMARY KEY,resource_state text NOT NULL,envelope bytea);
		CREATE TABLE public.cyb14_test_approvals(id text PRIMARY KEY,tenant_id uuid NOT NULL,subject_id text NOT NULL,action text NOT NULL,
		resource_id text NOT NULL,input_fingerprint text NOT NULL,resource_state text NOT NULL,issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false);
		ALTER TABLE public.cyb14_test_objects ENABLE ROW LEVEL SECURITY;ALTER TABLE public.cyb14_test_objects FORCE ROW LEVEL SECURITY;
		ALTER TABLE public.cyb14_test_approvals ENABLE ROW LEVEL SECURITY;ALTER TABLE public.cyb14_test_approvals FORCE ROW LEVEL SECURITY;
		CREATE POLICY object_tenant ON public.cyb14_test_objects TO cyber_runtime
		USING(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
		CREATE POLICY approval_tenant ON public.cyb14_test_approvals TO cyber_runtime
		USING(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
		GRANT SELECT,UPDATE ON public.cyb14_test_objects,public.cyb14_test_approvals TO cyber_runtime`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err := admin.Exec(context.Background(), `DROP TABLE public.cyb14_test_objects,public.cyb14_test_approvals;
		REVOKE cyber_runtime FROM cyb14_test_login;DROP ROLE cyb14_test_login`)
		if err != nil {
			t.Error(err)
		}
	}()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("cyb14_test_login", "cyb14-local-test-only")
	db, err := tenantdb.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boundary := &postgresBoundary{db: db}
	seedApproval := func(t *testing.T, f *fixture) {
		t.Helper()
		a := f.boundary.approval
		if _, err := admin.Exec(ctx, `DELETE FROM public.cyb14_test_approvals`); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO public.cyb14_test_approvals(id,tenant_id,subject_id,action,resource_id,input_fingerprint,resource_state,issued_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, a.ID, string(a.TenantID), string(a.Subject), a.Operation.Action, a.Operation.ResourceID, a.Operation.InputFingerprint, a.ResourceState, a.IssuedAt, a.ExpiresAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"round trip", "RLS cross tenant", "worker delegation", "write rollback", "state changed during KMS", "relabeled envelope"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.p.DB = boundary
			f.p.Approvals = postgresApprovals{}
			f.kms.inTx = &boundary.inTx
			storage := &postgresStorage{}
			if _, err := admin.Exec(ctx, `DELETE FROM public.cyb14_test_objects;DELETE FROM public.cyb14_test_approvals`); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `INSERT INTO public.cyb14_test_objects(tenant_id,resource_id,resource_state)VALUES($1,'test:object','test-state')`, string(tenantA)); err != nil {
				t.Fatal(err)
			}
			input := []byte("postgres-plaintext-secret")
			request := f.request(Encrypt, input, tenantA)
			seedApproval(t, f)
			if kind == "write rollback" {
				storage.failWrite = true
			}
			if kind == "state changed during KMS" {
				f.kms.onCall = func() {
					if _, err := admin.Exec(ctx, `UPDATE public.cyb14_test_objects SET resource_state='changed'`); err != nil {
						t.Fatal(err)
					}
				}
			}
			var envelope Envelope
			if kind == "worker delegation" {
				id, err := f.p.Delegate(f.ctx, request, "test-worker", f.now.Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				envelope, err = f.s.EncryptWorker(authorization.WithVerifiedWorker(ctx, "test-worker"), authorization.WorkerRequest{DelegationID: id, Operation: request.Operation, CorrelationID: request.CorrelationID}, storage, input)
			} else {
				envelope, err = f.s.Encrypt(f.ctx, request, storage, input)
			}
			if kind == "write rollback" || kind == "state changed during KMS" {
				var data []byte
				var consumed bool
				if err := admin.QueryRow(ctx, `SELECT envelope FROM public.cyb14_test_objects`).Scan(&data); err != nil {
					t.Fatal(err)
				}
				if err := admin.QueryRow(ctx, `SELECT consumed FROM public.cyb14_test_approvals`).Scan(&consumed); err != nil {
					t.Fatal(err)
				}
				if err == nil || data != nil || consumed || len(envelope.Payload.Ciphertext) > 0 {
					t.Fatal("failed final boundary persisted data/consumption")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			decryptCtx := f.ctx
			tenant := tenantA
			if kind == "RLS cross tenant" || kind == "relabeled envelope" {
				tenant = tenantB
				decryptCtx = authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "test-human"}), "test-api")
				if kind == "relabeled envelope" {
					envelope.Header.Binding.TenantID = tenantB
					data, _ := json.Marshal(envelope)
					if _, err := admin.Exec(ctx, `UPDATE public.cyb14_test_objects SET tenant_id=$1,envelope=$2`, string(tenantB), data); err != nil {
						t.Fatal(err)
					}
				}
			}
			request = f.request(Decrypt, nil, tenant)
			seedApproval(t, f)
			priorCalls := f.kms.calls
			plaintext, err := f.s.Decrypt(decryptCtx, request, storage)
			if kind == "RLS cross tenant" || kind == "relabeled envelope" {
				if err == nil || plaintext != nil {
					t.Fatal("cross-tenant decrypt succeeded")
				}
				if kind == "RLS cross tenant" && f.kms.calls != priorCalls {
					t.Fatal("KMS accessed data hidden by RLS")
				}
				return
			}
			if err != nil || !bytes.Equal(input, plaintext) {
				t.Fatalf("PG round trip failed: %v", err)
			}
		})
	}
}
