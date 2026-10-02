package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestMigrationDiagnosticsRedactCredentials(t *testing.T) {
	_, parseErr := migrationDatabaseURL("postgres://user:database-password-secret@localhost/%zz?access_token=access-secret")
	if parseErr == nil {
		t.Fatal("expected invalid URL")
	}
	for _, err := range []error{parseErr, errors.New("password=database-password-secret Authorization: Bearer access-secret")} {
		var sink bytes.Buffer
		reportError(&sink, "open_migrations", err)
		for _, secret := range []string{"database-password-secret", "access-secret", "postgres://"} {
			if strings.Contains(sink.String(), secret) {
				t.Fatalf("credential reached diagnostic sink: %s", sink.String())
			}
		}
		if !strings.Contains(sink.String(), `"stage":"open_migrations"`) || !strings.Contains(sink.String(), `"error":"[REDACTED]"`) {
			t.Fatalf("sanitized diagnostic missing: %s", sink.String())
		}
	}
}
