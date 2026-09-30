package tenantdb

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/tenantidentity"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	testTenantA = "a0b1c2d3-e4f5-4678-9abc-def012345678"
	testTenantB = "b0b1c2d3-e4f5-4678-9abc-def012345678"
)

func TestTenantIsolationAndTransactionLifecycle(t *testing.T) {
	adminURL := os.Getenv("CYB12_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set CYB12_TEST_DATABASE_URL to an isolated disposable PostgreSQL database to run RLS integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	defer admin.Close()

	if err := prepareTestDatabase(ctx, admin, adminURL); err != nil {
		t.Fatal(err)
	}

	// Temporary grants exercise the RLS write policy. The production migration
	// grants runtime SELECT only; membership mutation remains a separate workflow.
	if _, err := admin.Exec(ctx, `GRANT INSERT, UPDATE, DELETE ON cyber.tenant_memberships TO cyber_runtime`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `REVOKE INSERT, UPDATE, DELETE ON cyber.tenant_memberships FROM cyber_runtime`)
	}()

	for _, tenant := range []string{testTenantA, testTenantB} {
		if _, err := admin.Exec(ctx, `INSERT INTO cyber.tenants (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `INSERT INTO cyber.tenant_memberships (tenant_id, principal_id) VALUES ($1, 'member-a'), ($2, 'member-b') ON CONFLICT DO NOTHING`, testTenantA, testTenantB); err != nil {
		t.Fatal(err)
	}

	runtimeURL, err := prepareRuntimeLogin(ctx, admin, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, `REVOKE cyber_runtime FROM cyb12_test_runtime_login`); err != nil {
			t.Errorf("revoke test runtime role: %v", err)
			return
		}
		if _, err := admin.Exec(cleanupCtx, `DROP ROLE cyb12_test_runtime_login`); err != nil {
			t.Errorf("drop test runtime login: %v", err)
		}
	}()
	appDB, err := Open(ctx, runtimeURL)
	if err != nil {
		t.Fatalf("open application pool with least-privilege login: %v", err)
	}
	defer appDB.Close()
	db := appDB

	runtimeConfig, err := pgxpool.ParseConfig(runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig.MaxConns = 1 // force the same physical connection to be reused
	runtimeConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE cyber_runtime")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	leakTestDB := &DB{pool: pool}

	tenantA := mustTenantID(t, testTenantA)
	tenantB := mustTenantID(t, testTenantB)
	runID := fmt.Sprintf("cyb12-%d", time.Now().UnixNano())

	t.Run("cross tenant reads are hidden", func(t *testing.T) {
		for _, tenant := range []tenantidentity.TenantID{tenantA, tenantB} {
			var count int
			err := withTenantTx(ctx, db, tenant, func(tx TenantTx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships WHERE principal_id IN ('member-a', 'member-b')`).Scan(&count)
			})
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("tenant %s sees %d membership rows, want 1", tenant, count)
			}
		}
	})

	t.Run("application pool assumes the runtime role", func(t *testing.T) {
		var currentUser, sessionUser string
		if err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			return tx.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&currentUser, &sessionUser)
		}); err != nil {
			t.Fatal(err)
		}
		if currentUser != runtimeRole || sessionUser != "cyb12_test_runtime_login" {
			t.Fatalf("database identities current_user=%q session_user=%q", currentUser, sessionUser)
		}
	})

	t.Run("cross tenant insert is rejected", func(t *testing.T) {
		err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO cyber.tenant_memberships (tenant_id, principal_id) VALUES ($1, 'forbidden')`, testTenantB)
			return err
		})
		if !hasSQLState(err, "42501") {
			t.Fatalf("cross-tenant insert error = %v, want RLS policy violation (42501)", err)
		}
	})

	t.Run("cross tenant update and delete affect no rows", func(t *testing.T) {
		err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			updated, err := tx.Exec(ctx, `UPDATE cyber.tenant_memberships SET principal_id = 'changed' WHERE tenant_id = $1`, testTenantB)
			if err != nil {
				return err
			}
			if updated.RowsAffected() != 0 {
				return fmt.Errorf("cross-tenant update changed %d rows", updated.RowsAffected())
			}
			deleted, err := tx.Exec(ctx, `DELETE FROM cyber.tenant_memberships WHERE tenant_id = $1`, testTenantB)
			if err != nil {
				return err
			}
			if deleted.RowsAffected() != 0 {
				return fmt.Errorf("cross-tenant delete changed %d rows", deleted.RowsAffected())
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("commit persists within tenant and not across tenants", func(t *testing.T) {
		if err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO cyber.tenant_memberships (tenant_id, principal_id) VALUES ($1, $2)`, testTenantA, runID+"-committed")
			return err
		}); err != nil {
			t.Fatal(err)
		}

		for _, check := range []struct {
			tenant tenantidentity.TenantID
			want   int
		}{{tenantA, 1}, {tenantB, 0}} {
			var count int
			if err := withTenantTx(ctx, db, check.tenant, func(tx TenantTx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships WHERE principal_id = $1`, runID+"-committed").Scan(&count)
			}); err != nil {
				t.Fatal(err)
			}
			if count != check.want {
				t.Fatalf("tenant %s sees committed row count %d, want %d", check.tenant, count, check.want)
			}
		}
	})

	t.Run("callback error rolls back and connection is reusable", func(t *testing.T) {
		wantErr := errors.New("callback failed")
		err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO cyber.tenant_memberships (tenant_id, principal_id) VALUES ($1, $2)`, testTenantA, runID+"-rolled-back"); err != nil {
				return err
			}
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("WithTenantTx() error = %v, want callback error", err)
		}
		var count int
		if err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships WHERE principal_id = $1`, runID+"-rolled-back").Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("rolled-back row count = %d, want 0", count)
		}
	})

	t.Run("SQL error aborts transaction and does not leak context", func(t *testing.T) {
		err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO cyber.tenant_memberships (tenant_id, principal_id) VALUES ($1, 'member-a')`, testTenantA)
			if err == nil {
				return errors.New("duplicate membership insert unexpectedly succeeded")
			}
			return nil // force Commit on an aborted transaction
		})
		if err == nil {
			t.Fatal("commit of aborted transaction unexpectedly succeeded")
		}

		if err := withTenantTx(ctx, db, tenantB, func(tx TenantTx) error {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships WHERE principal_id = 'member-a'`).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("tenant B observed tenant A row after commit error: %d", count)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing transaction tenant setting sees no rows", func(t *testing.T) {
		var count int
		err := withTenantTx(ctx, db, tenantA, func(tx TenantTx) error {
			if _, err := tx.Exec(ctx, resetTenantContext); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships`).Scan(&count)
		})
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("query without tenant context returned %d rows, want 0", count)
		}
	})

	t.Run("missing authenticated identity is rejected", func(t *testing.T) {
		callbackCalled := false
		err := db.WithTenantTx(ctx, func(TenantTx) error {
			callbackCalled = true
			return nil
		})
		if !errors.Is(err, ErrAuthenticatedIdentityRequired) {
			t.Fatalf("WithTenantTx() error = %v, want ErrAuthenticatedIdentityRequired", err)
		}
		if callbackCalled {
			t.Fatal("tenant callback ran without authenticated identity")
		}
	})

	t.Run("pooled connection has no tenant context after transaction", func(t *testing.T) {
		if err := withTenantTx(ctx, leakTestDB, tenantA, func(TenantTx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("pooled query outside tenant transaction returned %d rows, want 0", count)
		}
	})

	t.Run("tenant read grants are least privilege", func(t *testing.T) {
		// The integration test temporarily grants writes above to verify RLS;
		// revoke and assert the baseline grant set after the test.
		if _, err := admin.Exec(ctx, `REVOKE INSERT, UPDATE, DELETE ON cyber.tenant_memberships FROM cyber_runtime`); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"cyber.tenants", "cyber.tenant_memberships"} {
			var canSelect bool
			if err := admin.QueryRow(ctx, `SELECT has_table_privilege('cyber_runtime', $1, 'SELECT')`, table).Scan(&canSelect); err != nil {
				t.Fatal(err)
			}
			if !canSelect {
				t.Errorf("cyber_runtime lacks SELECT privilege on %s", table)
			}
			for _, privilege := range []string{"INSERT", "UPDATE", "DELETE"} {
				var allowed bool
				if err := admin.QueryRow(ctx, `SELECT has_table_privilege('cyber_runtime', $1, $2)`, table, privilege).Scan(&allowed); err != nil {
					t.Fatal(err)
				}
				if allowed {
					t.Errorf("cyber_runtime has %s privilege on %s in the production baseline", privilege, table)
				}
			}
		}
		if _, err := admin.Exec(ctx, `GRANT INSERT, UPDATE, DELETE ON cyber.tenant_memberships TO cyber_runtime`); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("roles cannot bypass RLS", func(t *testing.T) {
		var unsafeRoleCount int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('cyber_runtime', 'cyber_migrator', 'cyb12_test_runtime_login') AND (rolsuper OR rolbypassrls OR (rolname IN ('cyber_runtime', 'cyber_migrator') AND rolcanlogin))`).Scan(&unsafeRoleCount); err != nil {
			t.Fatal(err)
		}
		if unsafeRoleCount != 0 {
			t.Fatalf("%d foundation database roles can bypass RLS", unsafeRoleCount)
		}
		var forcedCount int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_class WHERE oid IN ('cyber.tenants'::regclass, 'cyber.tenant_memberships'::regclass) AND relforcerowsecurity`).Scan(&forcedCount); err != nil {
			t.Fatal(err)
		}
		if forcedCount != 2 {
			t.Fatalf("FORCE ROW LEVEL SECURITY is active for %d tenant tables, want 2", forcedCount)
		}

		conn, err := admin.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE cyber_migrator`); err != nil {
			t.Fatal(err)
		}
		var ownerVisibleRows int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM cyber.tenant_memberships`).Scan(&ownerVisibleRows); err != nil {
			t.Fatal(err)
		}
		if ownerVisibleRows != 0 {
			t.Fatalf("FORCE ROW LEVEL SECURITY allowed table owner to read %d rows without a tenant policy", ownerVisibleRows)
		}
	})
}

func prepareTestDatabase(ctx context.Context, admin *pgxpool.Pool, adminURL string) error {
	bootstrapPath := filepath.Join("..", "..", "db", "bootstrap_roles.sql")
	bootstrap, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return fmt.Errorf("read role bootstrap: %w", err)
	}
	if _, err := admin.Exec(ctx, string(bootstrap)); err != nil {
		return fmt.Errorf("bootstrap database roles: %w", err)
	}
	if _, err := admin.Exec(ctx, `GRANT cyber_migrator, cyber_runtime TO CURRENT_USER`); err != nil {
		return fmt.Errorf("grant test administrator role membership: %w", err)
	}

	migrationURL := withRoleOptionValue(adminURL, "cyber_migrator")
	migrationURL, err = withMigrationsTable(migrationURL)
	if err != nil {
		return err
	}
	location, err := migrationSourceURL(filepath.Join("..", "..", "db", "migrations"))
	if err != nil {
		return fmt.Errorf("resolve migration directory: %w", err)
	}
	instance, err := migrate.New(location, migrationURL)
	if err != nil {
		return fmt.Errorf("open migrations: %w", err)
	}
	defer func() { _, _ = instance.Close() }()
	if err := instance.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func withRoleOptionValue(rawURL, role string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	query := parsed.Query()
	options := strings.TrimSpace(query.Get("options"))
	query.Set("options", strings.TrimSpace(options+" -c role="+role))
	parsed.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	return parsed.String()
}

func prepareRuntimeLogin(ctx context.Context, admin *pgxpool.Pool, adminURL string) (string, error) {
	const loginRole = "cyb12_test_runtime_login"
	// This fixed credential is only used in the isolated disposable integration
	// database and is removed at test cleanup. No input is interpolated into SQL.
	const password = "cyb12-local-test-only"

	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)`, loginRole).Scan(&exists); err != nil {
		return "", fmt.Errorf("check test login role: %w", err)
	}
	if exists {
		if _, err := admin.Exec(ctx, `ALTER ROLE cyb12_test_runtime_login LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'cyb12-local-test-only'`); err != nil {
			return "", fmt.Errorf("reset test login role: %w", err)
		}
	} else if _, err := admin.Exec(ctx, `CREATE ROLE cyb12_test_runtime_login LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'cyb12-local-test-only'`); err != nil {
		return "", fmt.Errorf("create test login role: %w", err)
	}
	if _, err := admin.Exec(ctx, `GRANT cyber_runtime TO cyb12_test_runtime_login`); err != nil {
		return "", fmt.Errorf("grant runtime role to test login: %w", err)
	}

	parsed, err := url.Parse(adminURL)
	if err != nil {
		return "", fmt.Errorf("parse test database URL: %w", err)
	}
	parsed.User = url.UserPassword(loginRole, password)
	return parsed.String(), nil
}

func withMigrationsTable(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("x-migrations-table", `"cyber"."schema_migrations"`)
	query.Set("x-migrations-table-quoted", "true")
	parsed.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
	return parsed.String(), nil
}

func migrationSourceURL(directory string) (string, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	path := filepath.ToSlash(abs)
	return "file://" + path, nil
}

func withTenantTx(ctx context.Context, db *DB, tenantID tenantidentity.TenantID, fn func(TenantTx) error) error {
	ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{
		TenantID: tenantID, PrincipalID: "cyb12-test-principal",
	})
	return db.WithTenantTx(ctx, fn)
}

func mustTenantID(t *testing.T, value string) tenantidentity.TenantID {
	t.Helper()
	id, err := tenantidentity.ParseTenantID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func hasSQLState(err error, want string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == want
}
