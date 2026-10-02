package encryption

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"cyber-ai-platform/internal/authorization"
)

func TestDecryptFinalDenialNeverReleasesPreparedPlaintext(t *testing.T) {
	for _, kind := range []string{"state", "expiry", "PDP", "CAS", "commit"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.encrypted(t, []byte("prepared-secret"))
			request := f.request(Decrypt, nil, tenantA)
			f.kms.onCall = func() {
				switch kind {
				case "state":
					f.store.state = "changed"
				case "expiry":
					f.now = f.now.Add(2 * time.Minute)
				case "PDP":
					f.p.Policy = policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
						return authorization.Decision{}, nil
					})
				case "CAS":
					f.store.finalCASFailure = true
				case "commit":
					f.boundary.failCommit = true
				}
			}
			plaintext, err := f.s.Decrypt(f.ctx, request, f.store)
			if err == nil || plaintext != nil || f.boundary.approval.Consumed {
				t.Fatal("failed final boundary released plaintext or consumed approval")
			}
		})
	}
}

func TestWorkerDecryptAndPreparationInputSnapshot(t *testing.T) {
	f := newFixture(t)
	input := []byte(`{"tenant_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","data":"secret"}`)
	original := append([]byte(nil), input...)
	request := f.request(Encrypt, input, tenantA)
	f.kms.onCall = func() { clear(input) }
	envelope, err := f.s.Encrypt(f.ctx, request, f.store, input)
	if err != nil || envelope.Header.Binding.TenantID != tenantA {
		t.Fatal("payload tenant became authoritative or input snapshot changed")
	}
	f.kms.onCall = nil
	request = f.request(Decrypt, nil, tenantA)
	id, err := f.p.Delegate(f.ctx, request, "test-worker", f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := f.s.DecryptWorker(authorization.WithVerifiedWorker(context.Background(), "test-worker"),
		authorization.WorkerRequest{DelegationID: id, Operation: request.Operation, CorrelationID: request.CorrelationID}, f.store)
	if err != nil || !bytes.Equal(plaintext, original) {
		t.Fatalf("worker decrypt did not use authoritative delegation: %v", err)
	}
}

func TestMissingSecurityDependenciesDoNotInvokeKMS(t *testing.T) {
	for _, kind := range []string{"PDP", "approvals", "DB", "PEP audit", "storage", "approval ID"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			input := []byte("secret")
			request := f.request(Encrypt, input, tenantA)
			var storage Storage = f.store
			switch kind {
			case "PDP":
				f.p.Policy = nil
			case "approvals":
				f.p.Approvals = nil
			case "DB":
				f.p.DB = nil
			case "PEP audit":
				f.p.Audit = nil
			case "storage":
				storage = nil
			case "approval ID":
				request.ApprovalID = ""
			}
			envelope, err := f.s.Encrypt(f.ctx, request, storage, input)
			if err == nil || f.kms.calls != 0 || len(envelope.Payload.Ciphertext) > 0 {
				t.Fatal("missing security dependency bypassed preparation gate")
			}
		})
	}
}

func TestKMSClassificationMasksSDKDetails(t *testing.T) {
	for _, item := range []struct {
		err  error
		want error
	}{
		{KMSFailure{Kind: Denied}, ErrDenied}, {&KMSFailure{Kind: Unavailable}, ErrUnavailable},
		{fmt.Errorf("SDK bearer secret: %w", KMSFailure{Kind: Timeout}), ErrTimeout},
		{KMSFailure{Kind: 99}, ErrDependency},
	} {
		if got := kmsError(item.err); got != item.want {
			t.Fatalf("classification = %v, want %v", got, item.want)
		}
	}
}
