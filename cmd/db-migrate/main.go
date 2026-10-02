package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"cyber-ai-platform/internal/audit"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "up" && os.Args[1] != "down") {
		fmt.Fprintln(os.Stderr, "usage: db-migrate up|down")
		os.Exit(2)
	}

	databaseURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "MIGRATIONS_DATABASE_URL is required")
		os.Exit(2)
	}

	resolvedURL, err := migrationDatabaseURL(databaseURL)
	if err != nil {
		reportError(os.Stderr, "invalid_database_url", err)
		os.Exit(2)
	}

	location, err := migrationSourceURL("db/migrations")
	if err != nil {
		reportError(os.Stderr, "resolve_migrations", err)
		os.Exit(1)
	}

	instance, err := migrate.New(location, resolvedURL)
	if err != nil {
		reportError(os.Stderr, "open_migrations", err)
		os.Exit(1)
	}
	defer func() {
		_, _ = instance.Close()
	}()

	if os.Args[1] == "up" {
		err = instance.Up()
	} else {
		err = instance.Down()
	}
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		reportError(os.Stderr, "apply_migrations", err)
		os.Exit(1)
	}
}

// Dependency/URL errors may contain passwords or connection strings. Keep a
// diagnostic stage but never stringify an error into a normal log sink.
func reportError(sink io.Writer, stage string, err error) {
	logger := audit.New(sink, "event", "stage", "error")
	_ = logger.Emit(map[string]any{"event": "migration_failed", "stage": stage, "error": err})
}

func migrationDatabaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return "", errors.New("expected a postgres:// or postgresql:// URL")
	}

	query := parsed.Query()
	options := strings.TrimSpace(query.Get("options"))
	query.Set("options", strings.TrimSpace(options+" -c role=cyber_migrator"))
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
	// The golang-migrate file source restores the full path as URL host + path.
	// Keeping the Windows drive (for example, C:) in the URL host preserves
	// the drive when that source joins the two components.
	return "file://" + path, nil
}
