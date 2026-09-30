// Package tenantdb provides the application's pooled PostgreSQL connection and
// the only supported tenant transaction boundary for this foundation.
package tenantdb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cyber-ai-platform/internal/tenantidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	runtimeRole        = "cyber_runtime"
	resetTenantContext = "SELECT set_config('app.tenant_id', '', false)"
)

var ErrAuthenticatedIdentityRequired = errors.New("authenticated tenant identity is required")

// DB deliberately keeps the pool private so application queries use
// WithTenantTx and cannot accidentally reuse a connection with another
// tenant's transaction context.
type DB struct {
	pool *pgxpool.Pool
}

// TenantTx exposes query operations without Commit or Rollback so the caller
// cannot bypass the transaction boundary managed by WithTenantTx.
type TenantTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Open creates and verifies the application-side pgxpool. The database login
// must be granted membership in cyber_runtime; the pool activates that role
// for each newly opened connection.
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE cyber_runtime")
		if err != nil {
			return fmt.Errorf("activate database runtime role: %w", err)
		}
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases all pooled database connections.
func (db *DB) Close() {
	db.pool.Close()
}

// WithTenantTx executes fn in a transaction with a transaction-local tenant
// context. The session setting is cleared before and after the transaction as
// defense in depth against a connection previously modified outside this API.
// The supplied tenant must come from trusted authentication middleware.
func (db *DB) WithTenantTx(ctx context.Context, fn func(TenantTx) error) (retErr error) {
	identity, ok := tenantidentity.FromContext(ctx)
	if !ok || strings.TrimSpace(identity.PrincipalID) == "" {
		return ErrAuthenticatedIdentityRequired
	}
	tenantID := identity.TenantID
	if _, err := tenantidentity.ParseTenantID(string(tenantID)); err != nil {
		return fmt.Errorf("invalid tenant context: %w", err)
	}
	if fn == nil {
		return errors.New("tenant transaction callback is required")
	}

	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire database connection: %w", err)
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	txClosed := false
	defer func() {
		cleanupCtx := ctx
		if ctx.Err() != nil {
			cleanupCtx = context.Background()
		}
		if !txClosed {
			if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				retErr = errors.Join(retErr, fmt.Errorf("rollback tenant transaction: %w", rollbackErr))
			}
		}
		if _, resetErr := conn.Exec(cleanupCtx, resetTenantContext); resetErr != nil {
			_ = conn.Conn().Close(context.Background())
			retErr = errors.Join(retErr, fmt.Errorf("clear pooled tenant context: %w", resetErr))
		}
	}()

	if _, err := tx.Exec(ctx, resetTenantContext); err != nil {
		return fmt.Errorf("clear prior tenant context: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", string(tenantID)); err != nil {
		return fmt.Errorf("set transaction tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		txClosed = true
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	txClosed = true
	return nil
}
