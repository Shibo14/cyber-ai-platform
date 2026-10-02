package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSecretsAreRedactedBeforeSink(t *testing.T) {
	fields := map[string]any{
		"password": "password-secret", "AccessToken": "access-secret",
		"refresh_token": "refresh-secret", "Authorization": "Bearer authorization-secret",
		"X-API-Key": "api-secret", "client_secret": "client-secret",
		"cookie": "cookie-secret", "Set-Cookie": []string{"set-cookie-secret"},
		"session_secret": "session-secret", "private_key": "private-secret",
		"database_url": "postgres://user:db-password-secret@localhost/database",
		"credentials":  map[string]any{"value": "credential-secret"},
		"nested": map[string]any{"status": "ok", "values": []any{
			map[string]any{"Password": "nested-secret", "count": 3},
			map[string]any{"metadata": "Bearer hidden-bearer-secret"},
		}},
		"event": "decision", "correlation_id": "job-1", "duration_ms": 12,
		"copied": "password-secret", "copied_token": "authorization-secret",
	}
	var sink bytes.Buffer
	allowed := make([]string, 0, len(fields))
	for key := range fields {
		allowed = append(allowed, key)
	}
	logger := New(&sink, allowed...)
	if err := logger.Emit(fields); err != nil {
		t.Fatal(err)
	}
	serialized := sink.String()
	for _, secret := range []string{"password-secret", "access-secret", "refresh-secret", "authorization-secret",
		"api-secret", "client-secret", "cookie-secret", "set-cookie-secret", "session-secret",
		"private-secret", "credential-secret", "nested-secret", "hidden-bearer-secret", "db-password-secret"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret %q reached sink: %s", secret, serialized)
		}
	}
	var output map[string]any
	if err := json.Unmarshal(sink.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"password", "AccessToken", "refresh_token", "Authorization", "X-API-Key",
		"client_secret", "cookie", "Set-Cookie", "session_secret", "private_key", "credentials", "database_url"} {
		if output[key] != Redacted {
			t.Errorf("%s = %v, want redacted", key, output[key])
		}
	}
	if output["event"] != "decision" || output["correlation_id"] != "job-1" || output["duration_ms"] != float64(12) {
		t.Fatalf("ordinary metadata lost: %v", output)
	}
	if fields["password"] != "password-secret" {
		t.Fatal("sanitizer mutated input")
	}
}

func TestUnlistedSecretCopiedIntoAllowedMetadata(t *testing.T) {
	var sink bytes.Buffer
	logger := New(&sink, "metadata", "event")
	if err := logger.Emit(map[string]any{
		"password": "unlisted-password-secret", "authorization": "Bearer\tunlisted-token-secret",
		"metadata": []any{"unlisted-password-secret", "prefix unlisted-token-secret suffix"}, "event": "decision",
	}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"unlisted-password-secret", "unlisted-token-secret"} {
		if strings.Contains(sink.String(), secret) {
			t.Fatalf("copied secret leaked: %s", sink.String())
		}
	}
}

type credentialObject struct{}

func (credentialObject) MarshalJSON() ([]byte, error) { panic("unsafe marshaler invoked") }
func (credentialObject) String() string               { panic("unsafe Stringer invoked") }

func TestAllowlistAndUnsafeObjects(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	var sink bytes.Buffer
	logger := New(&sink, "metadata", "safe", "cycle", "pem", "Bearer key-secret")
	if err := logger.Emit(map[string]any{
		"unlisted": "unlisted-secret", "metadata": credentialObject{},
		"safe": true, "cycle": cycle, "pem": "-----BEGIN RSA PRIVATE KEY-----\npem-secret",
		"Bearer key-secret": "secret-in-key", // keys also reach serialized logs
	}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"unlisted-secret", "pem-secret", "key-secret", "secret-in-key"} {
		if strings.Contains(sink.String(), secret) {
			t.Fatalf("secret leaked: %s", sink.String())
		}
	}
	if !strings.Contains(sink.String(), `"safe":true`) {
		t.Fatal("safe metadata was lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink password=never-log-me") }

func TestSinkFailureDoesNotExposeRawError(t *testing.T) {
	for _, logger := range []*Logger{New(nil, "event"), New(failingWriter{}, "event")} {
		if err := logger.Emit(map[string]any{"event": "decision"}); err != ErrEmit {
			t.Fatalf("Emit() error = %v", err)
		}
	}
}
