package encryption

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantidentity"
)

func TestSameTenantRoundTripAndKeyCleanup(t *testing.T) {
	f := newFixture(t)
	original := []byte("protected-plaintext-secret")
	envelope := f.encrypted(t, original)
	plaintext, err := f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
	if err != nil || !bytes.Equal(plaintext, original) {
		t.Fatalf("round trip failed: %v", err)
	}
	if !f.boundary.approval.Consumed {
		t.Fatal("final approval not consumed")
	}
	encoded, _ := json.Marshal(envelope)
	if bytes.Contains(encoded, original) {
		t.Fatal("plaintext fallback in envelope")
	}
	for _, key := range append(f.cipher.generated, f.kms.keys...) {
		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Fatal("key buffer not cleared")
		}
	}
	if !bytes.Equal(original, []byte("protected-plaintext-secret")) {
		t.Fatal("caller input was mutated")
	}
	if f.kms.insideTxCalls != 0 {
		t.Fatal("KMS called inside a tenant transaction")
	}
}

func TestTenantAndMetadataTamperingDenied(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Envelope)
	}{
		{"tenant", func(e *Envelope) { e.Header.Binding.TenantID = tenantB }},
		{"profile", func(e *Envelope) { e.Header.Binding.ProfileID = "unknown" }},
		{"suite", func(e *Envelope) { e.Header.Binding.SuiteID = "unknown" }},
		{"key reference", func(e *Envelope) { e.Header.KeyReference = "attacker-key" }},
		{"wrapped DEK", func(e *Envelope) { e.Header.WrappedDEK[len(e.Header.WrappedDEK)-1] ^= 1 }},
		{"ciphertext", func(e *Envelope) { e.Payload.Ciphertext[0] ^= 1 }},
		{"nonce", func(e *Envelope) { e.Payload.Nonce[0] ^= 1 }},
		{"tag", func(e *Envelope) { e.Payload.Tag[0] ^= 1 }},
		{"missing metadata", func(e *Envelope) { e.Header = Header{} }},
		{"missing wrapped DEK", func(e *Envelope) { e.Header.WrappedDEK = nil }},
		{"corrupt nonce", func(e *Envelope) { e.Payload.Nonce = []byte{1} }},
		{"missing tag", func(e *Envelope) { e.Payload.Tag = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			envelope := f.encrypted(t, []byte("sensitive-test-data"))
			tc.mutate(&envelope)
			f.store.envelope = envelope
			plaintext, err := f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
			assertDenied(t, plaintext, err)
			if f.boundary.approval.Consumed {
				t.Fatal("failed decrypt consumed approval")
			}
		})
	}
	t.Run("different tenant", func(t *testing.T) {
		f := newFixture(t)
		f.encrypted(t, []byte("tenant-A-secret"))
		ctx := authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(), tenantidentity.Identity{TenantID: tenantB, PrincipalID: "test-human"}), "test-api")
		plaintext, err := f.s.Decrypt(ctx, f.request(Decrypt, nil, tenantB), f.store)
		assertDenied(t, plaintext, err)
	})
	t.Run("relabeled entire envelope", func(t *testing.T) {
		f := newFixture(t)
		f.encrypted(t, []byte("tenant-A-secret"))
		f.store.envelope.Header.Binding.TenantID = tenantB
		ctx := authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(), tenantidentity.Identity{TenantID: tenantB, PrincipalID: "test-human"}), "test-api")
		plaintext, err := f.s.Decrypt(ctx, f.request(Decrypt, nil, tenantB), f.store)
		assertDenied(t, plaintext, err)
	})
}

func TestAADAndKMSContextMismatchDenied(t *testing.T) {
	for _, kind := range []string{"AAD", "KMS context", "wrapped DEK swapping"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			first := f.encrypted(t, []byte("first-secret"))
			switch kind {
			case "AAD":
				f.cipher.wrongAAD = true
			case "KMS context":
				f.kms.wrongContext = true
			case "wrapped DEK swapping":
				second := f.encrypted(t, []byte("second-secret"))
				first.Header.WrappedDEK = second.Header.WrappedDEK
				f.store.envelope = first
			}
			plaintext, err := f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
			assertDenied(t, plaintext, err)
		})
	}
}

func TestKMSFailuresFailClosedWithoutFallback(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		corrupt string
		want    error
	}{
		{"unavailable", KMSFailure{Kind: Unavailable}, "", ErrUnavailable},
		{"denied", KMSFailure{Kind: Denied}, "", ErrDenied},
		{"timeout", context.DeadlineExceeded, "", ErrTimeout},
		{"canceled", context.Canceled, "", ErrCanceled},
		{"classified corrupt", KMSFailure{Kind: CorruptResponse}, "", ErrCorruptResponse},
		{"raw SDK error", errors.New("Authorization: Bearer sdk-secret key=DEK-secret"), "", ErrDependency},
		{"empty wrap", nil, "empty_wrap", ErrCorruptResponse},
		{"garbage wrap", nil, "garbage_wrap", ErrCorruptResponse},
		{"plaintext wrap", nil, "plaintext_wrap", ErrCorruptResponse},
		{"short key", nil, "short_key", ErrCorruptResponse},
		{"valid length wrong key", nil, "wrong_key", ErrCorruptResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			request := f.request(Encrypt, []byte("plaintext-secret"), tenantA)
			f.kms.failure = tc.err
			f.kms.corrupt = tc.corrupt
			envelope, err := f.s.Encrypt(f.ctx, request, f.store, []byte("plaintext-secret"))
			if err != tc.want || len(envelope.Payload.Ciphertext) != 0 || f.store.stores != 0 || f.boundary.approval.Consumed {
				t.Fatalf("failed encrypt released/persisted data: %v", err)
			}
			for _, secret := range []string{"plaintext-secret", "sdk-secret", "DEK-secret", "partial-sdk-secret", "invalid-key-secret"} {
				if strings.Contains(f.sink.String(), secret) || strings.Contains(err.Error(), secret) {
					t.Fatal("secret leaked")
				}
			}
		})
	}
	for _, tc := range cases[:6] {
		t.Run("decrypt "+tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.encrypted(t, []byte("plaintext-secret"))
			f.kms.failure = tc.err
			plaintext, err := f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
			if err != tc.want || plaintext != nil || f.boundary.approval.Consumed {
				t.Fatalf("failed decrypt returned plaintext/consumed approval: %v", err)
			}
		})
	}
	t.Run("cipher returns partial plaintext on error", func(t *testing.T) {
		f := newFixture(t)
		f.encrypted(t, []byte("plaintext-secret"))
		f.cipher.openError = true
		plaintext, err := f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
		assertDenied(t, plaintext, err)
		for _, partial := range f.cipher.opened {
			if !bytes.Equal(partial, make([]byte, len(partial))) {
				t.Fatal("partial plaintext not cleared")
			}
		}
	})
}

func TestAuthorizationApprovalAndFinalChecks(t *testing.T) {
	for _, kind := range []string{"missing identity", "subject denied", "actor denied", "PDP unavailable", "approval mismatch", "replay", "changed plaintext", "state changed during KMS", "approval expired during KMS", "final PDP denied", "final CAS", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			input := []byte("approved-input")
			request := f.request(Encrypt, input, tenantA)
			ctx := f.ctx
			expectedCalls := false
			switch kind {
			case "missing identity":
				ctx = context.Background()
			case "subject denied":
				f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{ActorAllowed: true}, nil
				})
			case "actor denied":
				f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{SubjectAllowed: true}, nil
				})
			case "PDP unavailable":
				f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{}, errors.New("PDP secret")
				})
			case "approval mismatch":
				f.boundary.approval.TenantID = tenantB
			case "replay":
				f.boundary.approval.Consumed = true
			case "changed plaintext":
				input = []byte("changed-input")
			case "state changed during KMS":
				expectedCalls = true
				f.kms.onCall = func() { f.store.state = "changed" }
			case "approval expired during KMS":
				expectedCalls = true
				f.kms.onCall = func() { f.now = f.now.Add(2 * time.Minute) }
			case "final PDP denied":
				expectedCalls = true
				f.kms.onCall = func() {
					f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
						return authorization.Decision{}, nil
					})
				}
			case "final CAS":
				expectedCalls = true
				f.store.finalCASFailure = true
			case "rollback":
				expectedCalls = true
				f.store.failWrite = true
			}
			envelope, err := f.s.Encrypt(ctx, request, f.store, input)
			if err == nil || len(envelope.Payload.Ciphertext) != 0 || f.store.stores != 0 {
				t.Fatal("unauthorized/failed operation succeeded")
			}
			if !expectedCalls && f.kms.calls != 0 {
				t.Fatal("KMS invoked before required authorization/approval checks")
			}
			if kind != "replay" && f.boundary.approval.Consumed {
				t.Fatal("failed final transaction consumed approval")
			}
		})
	}
}

func TestWorkerDelegationIsAuthoritative(t *testing.T) {
	for _, kind := range []string{"success", "unknown reference", "wrong worker", "changed operation", "conflicting identity", "worker direct path", "expired during KMS", "subject denied"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			input := []byte("worker-secret")
			request := f.request(Encrypt, input, tenantA)
			id, err := f.p.Delegate(f.ctx, request, "test-worker", f.now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			worker := authorization.WorkerRequest{DelegationID: id, Operation: request.Operation, CorrelationID: request.CorrelationID}
			ctx := authorization.WithVerifiedWorker(context.Background(), "test-worker")
			switch kind {
			case "unknown reference":
				worker.DelegationID = "forged"
			case "wrong worker":
				ctx = authorization.WithVerifiedWorker(context.Background(), "other-worker")
			case "changed operation":
				worker.Operation.ResourceID = "different"
			case "conflicting identity":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: tenantB, PrincipalID: "test-human"})
			case "expired during KMS":
				f.kms.onCall = func() { f.now = f.now.Add(2 * time.Minute) }
			case "subject denied":
				f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{ActorAllowed: true}, nil
				})
			}
			var envelope Envelope
			if kind == "worker direct path" {
				envelope, err = f.s.Encrypt(ctx, request, f.store, input)
			} else {
				envelope, err = f.s.EncryptWorker(ctx, worker, f.store, input)
			}
			if kind == "success" {
				if err != nil || f.store.lastTenant != tenantA || len(envelope.Payload.Ciphertext) == 0 {
					t.Fatalf("delegation authority failed: %v", err)
				}
			} else if err == nil || len(envelope.Payload.Ciphertext) != 0 || f.store.stores != 0 {
				t.Fatal("worker bypass succeeded")
			}
		})
	}
}

type secretWriter struct{}

func (secretWriter) Write([]byte) (int, error) {
	return 0, errors.New("audit credential=secret-sink-key")
}

func TestAuditContainsOnlySanitizedMetadataAndFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.encrypted(t, []byte("audit-plaintext-secret"))
	f.kms.failure = KMSFailure{Kind: Unavailable}
	_, _ = f.s.Decrypt(f.ctx, f.request(Decrypt, nil, tenantA), f.store)
	if !strings.Contains(f.sink.String(), `"event":"kms_access"`) || !strings.Contains(f.sink.String(), `"failure_class":"unavailable"`) {
		t.Fatal("KMS access/failure events missing")
	}
	for _, line := range strings.Split(strings.TrimSpace(f.sink.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"plaintext", "dek", "key", "wrapped_dek", "key_reference", "error", "request", "response"} {
			if _, ok := event[field]; ok {
				t.Fatalf("unsafe audit field %s", field)
			}
		}
	}
	for _, secret := range []string{"audit-plaintext-secret", hex.EncodeToString(f.kms.kek), base64.StdEncoding.EncodeToString(f.kms.kek)} {
		if strings.Contains(f.sink.String(), secret) {
			t.Fatal("key/plaintext in audit")
		}
	}
	for _, encoded := range f.cipher.encodedKeys {
		key, _ := hex.DecodeString(encoded)
		for _, representation := range []string{encoded, base64.StdEncoding.EncodeToString(key), string(key)} {
			if strings.Contains(f.sink.String(), representation) {
				t.Fatal("plaintext DEK reached audit output")
			}
		}
	}
	for _, stage := range []string{"KMS audit", "final PEP audit"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			f.encrypted(t, []byte("secret"))
			request := f.request(Decrypt, nil, tenantA)
			if stage == "KMS audit" {
				f.s.config.Audit = audit.New(secretWriter{}, "event")
			} else {
				f.kms.onCall = func() { f.p.Audit = audit.New(secretWriter{}, "event") }
			}
			plaintext, err := f.s.Decrypt(f.ctx, request, f.store)
			if plaintext != nil || err != ErrDependency || strings.Contains(err.Error(), "secret-sink-key") {
				t.Fatal("audit failure leaked output/error")
			}
		})
	}
}

func TestMissingConfigurationHasNoFallback(t *testing.T) {
	f := newFixture(t)
	for _, kind := range []string{"KMS", "cipher", "keys", "audit", "PEP", "profile"} {
		t.Run(kind, func(t *testing.T) {
			config := f.s.config
			switch kind {
			case "KMS":
				config.KMS = nil
			case "cipher":
				config.Cipher = nil
			case "keys":
				config.Keys = nil
			case "audit":
				config.Audit = nil
			case "PEP":
				config.PEP = nil
			case "profile":
				config.ProfileID = ""
			}
			if service, err := New(config); service != nil || err != ErrDependency {
				t.Fatal("missing dependency selected a default/fallback")
			}
		})
	}
}
