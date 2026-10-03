package queue

// Algorithms, JSON AAD, operation names, wire fields and repositories here are
// disposable TEST FIXTURES. They select no production crypto/schema/workflow.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/encryption"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

const protectedTenantA tenantidentity.TenantID = "a0b1c2d3-e4f5-4678-9abc-def012345678"
const protectedTenantB tenantidentity.TenantID = "b0b1c2d3-e4f5-4678-9abc-def012345678"

type protectedPolicy func(context.Context, authorization.Execution) (authorization.Decision, error)

func (f protectedPolicy) Evaluate(ctx context.Context, e authorization.Execution) (authorization.Decision, error) {
	return f(ctx, e)
}

type protectedDelegations struct {
	records map[string]authorization.Delegation
}

func (s *protectedDelegations) Create(_ context.Context, d authorization.Delegation) error {
	if _, exists := s.records[d.ID]; exists {
		return errors.New("duplicate immutable delegation")
	}
	s.records[d.ID] = d
	return nil
}
func (s *protectedDelegations) Load(_ context.Context, id string) (authorization.Delegation, error) {
	d, exists := s.records[id]
	if !exists {
		return authorization.Delegation{}, errors.New("unknown delegation")
	}
	return d, nil
}

type protectedBoundary struct {
	approval     authorization.Approval
	operation    authorization.Operation
	objectTenant tenantidentity.TenantID
	state        string
	envelope     encryption.Envelope
	executions   int
	inTx         bool
}

func (b *protectedBoundary) WithTenantTx(ctx context.Context, fn func(tenantdb.TenantTx) error) error {
	if _, ok := tenantidentity.FromContext(ctx); !ok {
		return authorization.ErrDenied
	}
	before := b.approval
	executions := b.executions
	b.inTx = true
	err := fn(nil)
	b.inTx = false
	if err != nil {
		b.approval = before
		b.executions = executions
	}
	return err
}
func (b *protectedBoundary) Load(ctx context.Context, _ tenantdb.TenantTx, id string) (authorization.Approval, error) {
	i, ok := tenantidentity.FromContext(ctx)
	if !ok || i.TenantID != b.approval.TenantID || id != b.approval.ID {
		return authorization.Approval{}, authorization.ErrDenied
	}
	return b.approval, nil
}
func (b *protectedBoundary) Consume(_ context.Context, _ tenantdb.TenantTx, _ string) (bool, error) {
	if b.approval.Consumed {
		return false, nil
	}
	b.approval.Consumed = true
	return true, nil
}
func (b *protectedBoundary) LockState(ctx context.Context, _ tenantdb.TenantTx, e authorization.Execution) (string, error) {
	i, ok := tenantidentity.FromContext(ctx)
	if !ok || i.TenantID != b.objectTenant || i.TenantID != e.TenantID || e.Operation != b.operation {
		return "", authorization.ErrDenied
	}
	return b.state, nil
}
func (b *protectedBoundary) ExecuteIfState(_ context.Context, _ tenantdb.TenantTx, _ authorization.Execution, expected string) error {
	if b.state != expected {
		return authorization.ErrState
	}
	b.executions++
	return nil
}

// protectedStorage uses only the PEP-provided tenant transaction. All fixtures
// share one object, so copying another tenant's envelope cannot grant access.
type protectedStorage struct{ boundary *protectedBoundary }

func (s protectedStorage) Operation(e authorization.Execution, input encryption.Inputs) (authorization.Operation, error) {
	if input.Mode != encryption.Decrypt || input.Binding.TenantID != e.TenantID {
		return authorization.Operation{}, authorization.ErrDenied
	}
	return s.boundary.operation, nil
}
func (s protectedStorage) LockState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (string, error) {
	return s.boundary.LockState(ctx, tx, e)
}
func (s protectedStorage) Load(ctx context.Context, _ tenantdb.TenantTx, e authorization.Execution) (encryption.Envelope, error) {
	i, ok := tenantidentity.FromContext(ctx)
	if !ok || i.TenantID != s.boundary.objectTenant || e.TenantID != i.TenantID {
		return encryption.Envelope{}, authorization.ErrDenied
	}
	return s.boundary.envelope, nil
}
func (s protectedStorage) StoreIfState(context.Context, tenantdb.TenantTx, authorization.Execution, string, encryption.Envelope) error {
	return authorization.ErrDenied
}
func (s protectedStorage) CheckState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string) error {
	state, err := s.LockState(ctx, tx, e)
	if err != nil {
		return err
	}
	if state != expected {
		return authorization.ErrState
	}
	return nil
}

type protectedFixture struct {
	pep         *authorization.PEP
	boundary    *protectedBoundary
	delegations *protectedDelegations
	request     authorization.Request
	ctx         context.Context
	worker      context.Context
	now         time.Time
	log         bytes.Buffer
	schema      *Schema
	policyCalls int
}

func newProtectedFixture(t *testing.T) *protectedFixture {
	t.Helper()
	f := &protectedFixture{now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	f.ctx = authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(), tenantidentity.Identity{TenantID: protectedTenantA, PrincipalID: "fixture-user"}), "fixture-api")
	f.worker = authorization.WithVerifiedWorker(context.Background(), "fixture-worker")
	f.request = authorization.Request{Operation: authorization.Operation{Action: "fixture.protected", ResourceID: "fixture:object", InputFingerprint: "fixture-input"}, CorrelationID: "fixture-correlation", ApprovalID: "fixture-approval"}
	f.boundary = &protectedBoundary{operation: f.request.Operation, objectTenant: protectedTenantA, state: "fixture-state", approval: authorization.Approval{ID: f.request.ApprovalID, TenantID: protectedTenantA, Subject: "fixture-user", Operation: f.request.Operation, ResourceState: "fixture-state", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}}
	f.delegations = &protectedDelegations{records: make(map[string]authorization.Delegation)}
	f.pep = &authorization.PEP{DB: f.boundary, Approvals: f.boundary, Delegations: f.delegations, Now: func() time.Time { return f.now }, Audit: audit.New(&f.log, "event", "outcome", "failure_class", "tenant_id", "actor_id", "subject_id", "action", "resource_id", "correlation_id")}
	f.pep.Policy = protectedPolicy(func(ctx context.Context, e authorization.Execution) (authorization.Decision, error) {
		f.policyCalls++
		i, ok := tenantidentity.FromContext(ctx)
		if !ok || i.TenantID != e.TenantID || i.PrincipalID != string(e.Subject) {
			t.Fatal("PDP did not receive trusted delegation identity")
		}
		return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	var err error
	f.schema, err = NewSchema(SchemaConfig{ID: "fixture-schema", Version: "fixture-version", SchemaField: "fixture_schema", VersionField: "fixture_version", ReferenceField: "fixture_reference", ValidReference: func(s string) bool { decoded, err := hex.DecodeString(s); return err == nil && len(decoded) == 16 }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *protectedFixture) metadata(t *testing.T) Metadata {
	t.Helper()
	id, err := f.pep.Delegate(f.ctx, f.request, "fixture-worker", f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return f.schema.Metadata(id)
}
func (f *protectedFixture) processor(t *testing.T) *ProtectedProcessor {
	t.Helper()
	p, err := NewProtectedProcessor(ProtectedConfig{PEP: f.pep, Tool: func(_ context.Context, r authorization.WorkerRequest) (authorization.Tool, error) {
		if r.Operation != f.boundary.operation {
			return nil, authorization.ErrDenied
		}
		return f.boundary, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProtectedQueueWorkerAuthority(t *testing.T) {
	for _, name := range []string{"allowed", "unverified", "non-worker", "wrong-worker-after-claim", "cross-tenant-context", "cross-tenant-resource", "subject-denied", "actor-denied", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := newProtectedFixture(t)
			m := f.metadata(t)
			p := f.processor(t)
			ctx := f.worker
			switch name {
			case "unverified":
				ctx = context.Background()
			case "non-worker":
				ctx = authorization.WithVerifiedActor(context.Background(), "fixture-worker")
			case "wrong-worker-after-claim":
				ctx = authorization.WithVerifiedWorker(context.Background(), "claimed-consumer")
			case "cross-tenant-context":
				ctx = tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{TenantID: protectedTenantB, PrincipalID: "fixture-user"})
			case "cross-tenant-resource":
				f.boundary.objectTenant = protectedTenantB
			case "subject-denied":
				f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{ActorAllowed: true}, nil
				})
			case "actor-denied":
				f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
					return authorization.Decision{SubjectAllowed: true}, nil
				})
			case "expired":
				f.now = f.now.Add(2 * time.Minute)
			}
			err := p.Process(ctx, m)
			if name == "allowed" {
				if err != nil || f.boundary.executions != 1 || !f.boundary.approval.Consumed {
					t.Fatalf("allowed processing: %v", err)
				}
			} else if err == nil || f.boundary.executions != 0 || f.boundary.approval.Consumed {
				t.Fatalf("unauthorized processing: %v", err)
			}
		})
	}
}

func TestProtectedQueueFreshPDPAndOneShotRetry(t *testing.T) {
	f := newProtectedFixture(t)
	m := f.metadata(t)
	p := f.processor(t)
	if err := p.Authorize(f.worker, m); err != nil {
		t.Fatal(err)
	}
	f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		return authorization.Decision{ActorAllowed: true}, nil
	})
	if err := p.Process(f.worker, m); err == nil || f.boundary.executions != 0 {
		t.Fatal("queue preflight cached permission")
	}
	f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
	})
	if err := p.Process(f.worker, m); err != nil {
		t.Fatal(err)
	}
	// ACK-only authorization may inspect a completed reference but cannot make
	// its consumed approval reusable or execute another business mutation.
	if err := p.Authorize(f.worker, m); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(f.worker, m); Classify(err) != (Classification{Permanent, Denied}) || f.boundary.executions != 1 {
		t.Fatalf("consumed approval reused: %v", err)
	}
	// Permission changes also apply to completion/ACK-only recovery.
	f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		return authorization.Decision{}, nil
	})
	if err := p.Authorize(f.worker, m); err == nil {
		t.Fatal("ACK-only recovery bypassed fresh PDP")
	}
}

type protectedBroker struct {
	fields           Fields
	published, acked int
	ackErr           error
	pending          []Pending
}

func (*protectedBroker) Key(id string) (DeliveryKey, error) {
	return DeliveryKey{Stream: "fixture-stream", Group: "fixture-group", ID: id}, nil
}
func (b *protectedBroker) Publish(_ context.Context, fields Fields) (string, error) {
	b.fields = fields
	b.published++
	return "1-0", nil
}
func (b *protectedBroker) Read(context.Context, int64) ([]Delivery, error) {
	return []Delivery{{ID: "1-0", Fields: b.fields}}, nil
}
func (b *protectedBroker) Pending(context.Context, int64) ([]Pending, error) { return b.pending, nil }
func (b *protectedBroker) Claim(context.Context, []string, time.Duration) ([]Delivery, error) {
	return []Delivery{{ID: "1-0", Fields: b.fields}}, nil
}
func (b *protectedBroker) Ack(context.Context, string) error                  { b.acked++; return b.ackErr }
func (*protectedBroker) WriteDLQ(context.Context, DeadLetter) (string, error) { return "2-0", nil }

func TestProtectedProducerOnlyDelegationLocator(t *testing.T) {
	f := newProtectedFixture(t)
	broker := &protectedBroker{}
	producer, err := NewProducer(ProducerConfig{PEP: f.pep, Schema: f.schema, Broker: broker, Audit: f.pep.Audit})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := producer.Enqueue(f.ctx, f.request, "fixture-worker", f.now.Add(time.Minute)); err != nil || id != "1-0" {
		t.Fatalf("enqueue: %q,%v", id, err)
	}
	if len(broker.fields) != 3 {
		t.Fatal("extra payload/authority fields published")
	}
	m, err := f.schema.Decode(broker.fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := f.delegations.records[m.Reference]; !exists {
		t.Fatal("producer did not create authoritative delegation")
	}
	if err := f.processor(t).Process(f.worker, m); err != nil {
		t.Fatal(err)
	}
	if err := broker.Ack(f.worker, "1-0"); err != nil {
		t.Fatal(err)
	}
	if f.boundary.executions != 1 || broker.acked != 1 {
		t.Fatal("protected produce/process/ACK path failed")
	}
	if _, err := producer.Enqueue(context.Background(), f.request, "fixture-worker", f.now.Add(time.Minute)); err == nil || broker.published != 1 {
		t.Fatal("untrusted producer published")
	}
	for _, field := range []string{"tenant_id", "worker", "subject", "approval", "payload", "secret", "retry"} {
		if _, ok := broker.fields[field]; ok {
			t.Fatalf("queue authority/payload field %s", field)
		}
	}
}

type protectedCipher struct{}

func (protectedCipher) ID() string { return "fixture-only-aead" }
func (protectedCipher) GenerateKey(context.Context) ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}
func (protectedCipher) ValidateKey(k []byte) bool { return len(k) == 32 }
func (protectedCipher) ValidatePayload(p encryption.Payload) bool {
	return len(p.Nonce) == 12 && len(p.Tag) == 16
}
func protectedAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (protectedCipher) Seal(_ context.Context, key, plaintext []byte, h encryption.Header) (encryption.Payload, error) {
	aead, err := protectedAEAD(key)
	if err != nil {
		return encryption.Payload{}, err
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return encryption.Payload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return encryption.Payload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	return encryption.Payload{Nonce: nonce, Ciphertext: sealed[:len(sealed)-aead.Overhead()], Tag: sealed[len(sealed)-aead.Overhead():]}, nil
}
func (protectedCipher) Open(_ context.Context, key []byte, p encryption.Payload, h encryption.Header) ([]byte, error) {
	aead, err := protectedAEAD(key)
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte(nil), p.Ciphertext...), p.Tag...)
	return aead.Open(nil, p.Nonce, sealed, aad)
}

type protectedKMS struct {
	kek      []byte
	failure  error
	calls    int
	boundary *protectedBoundary
}

func protectedContextAAD(ref string, b encryption.Binding) []byte {
	data, _ := json.Marshal(struct {
		Key     string
		Binding encryption.Binding
	}{ref, b})
	return data
}
func (k *protectedKMS) Wrap(_ context.Context, ref string, key []byte, b encryption.Binding) ([]byte, error) {
	aead, err := protectedAEAD(k.kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, key, protectedContextAAD(ref, b)), nil
}
func (k *protectedKMS) Unwrap(_ context.Context, ref string, wrapped []byte, b encryption.Binding) ([]byte, error) {
	k.calls++
	if k.boundary.inTx {
		return nil, errors.New("KMS inside tenant transaction")
	}
	if k.failure != nil {
		return []byte("partial-DEK-secret"), k.failure
	}
	aead, err := protectedAEAD(k.kek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize()+aead.Overhead() {
		return nil, encryption.KMSFailure{Kind: encryption.CorruptResponse}
	}
	key, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], protectedContextAAD(ref, b))
	if err != nil {
		return nil, encryption.KMSFailure{Kind: encryption.Denied}
	}
	return key, nil
}

type protectedKeys struct{}

func (protectedKeys) EncryptionKey(authorization.Execution) (string, error) {
	return "fixture-key", nil
}
func (protectedKeys) AllowDecryptionKey(_ authorization.Execution, ref string) bool {
	return ref == "fixture-key"
}

func (f *protectedFixture) decryptProcessor(t *testing.T) (*ProtectedProcessor, *protectedKMS) {
	t.Helper()
	suite := protectedCipher{}
	key, err := suite.GenerateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	kek, err := suite.GenerateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kms := &protectedKMS{kek: kek, boundary: f.boundary}
	binding := encryption.Binding{TenantID: protectedTenantA, ProfileID: "fixture-profile", SuiteID: suite.ID()}
	wrapped, err := kms.Wrap(context.Background(), "fixture-key", key, binding)
	if err != nil {
		t.Fatal(err)
	}
	header := encryption.Header{Binding: binding, KeyReference: "fixture-key", WrappedDEK: wrapped}
	payload, err := suite.Seal(context.Background(), key, []byte("raw-payload-secret-token-plaintext-DEK"), header)
	if err != nil {
		t.Fatal(err)
	}
	f.boundary.envelope = encryption.Envelope{Header: header, Payload: payload}
	service, err := encryption.New(encryption.Config{PEP: f.pep, KMS: kms, Cipher: suite, Keys: protectedKeys{}, Audit: f.pep.Audit, ProfileID: "fixture-profile"})
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProtectedProcessor(ProtectedConfig{PEP: f.pep, Decrypt: func(context.Context, authorization.WorkerRequest) (*encryption.Service, encryption.Storage, error) {
		return service, protectedStorage{f.boundary}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return processor, kms
}

func TestProtectedQueueDecryptFailClosedAndNoSecrets(t *testing.T) {
	for _, name := range []string{"success", "KMS-unavailable", "KMS-timeout", "KMS-denied", "raw-KMS-error", "cross-tenant-envelope", "modified-ciphertext", "wrong-worker"} {
		t.Run(name, func(t *testing.T) {
			f := newProtectedFixture(t)
			m := f.metadata(t)
			processor, kms := f.decryptProcessor(t)
			ctx := f.worker
			switch name {
			case "KMS-unavailable":
				kms.failure = encryption.KMSFailure{Kind: encryption.Unavailable}
			case "KMS-timeout":
				kms.failure = encryption.KMSFailure{Kind: encryption.Timeout}
			case "KMS-denied":
				kms.failure = encryption.KMSFailure{Kind: encryption.Denied}
			case "raw-KMS-error":
				kms.failure = errors.New("credential=raw-sdk-secret")
			case "cross-tenant-envelope":
				f.boundary.envelope.Header.Binding.TenantID = protectedTenantB
			case "modified-ciphertext":
				f.boundary.envelope.Payload.Ciphertext[0] ^= 1
			case "wrong-worker":
				ctx = authorization.WithVerifiedWorker(context.Background(), "other-worker")
			}
			err := processor.Process(ctx, m)
			if name == "success" {
				if err != nil || !f.boundary.approval.Consumed {
					t.Fatalf("decrypt: %v", err)
				}
			} else if err == nil || f.boundary.approval.Consumed {
				t.Fatalf("failed decrypt completed/consumed: %v", err)
			}
			if name == "wrong-worker" || name == "cross-tenant-envelope" {
				if kms.calls != 0 {
					t.Fatal("denied decrypt accessed KMS")
				}
			}
			for _, secret := range []string{"raw-payload-secret", "raw-sdk-secret", "partial-DEK-secret", hex.EncodeToString(kms.kek)} {
				if strings.Contains(f.log.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
					t.Fatal("secret leaked through queue audit/error")
				}
			}
			if f.boundary.executions != 0 {
				t.Fatal("decrypt mode ran a separate unapproved business operation")
			}
		})
	}
}

func TestProtectedQueueConfigurationRejectsUngatedModes(t *testing.T) {
	f := newProtectedFixture(t)
	tool := func(context.Context, authorization.WorkerRequest) (authorization.Tool, error) { return f.boundary, nil }
	decrypt := func(context.Context, authorization.WorkerRequest) (*encryption.Service, encryption.Storage, error) {
		return nil, nil, nil
	}
	for _, config := range []ProtectedConfig{{}, {PEP: f.pep}, {PEP: f.pep, Tool: tool, Decrypt: decrypt}} {
		if _, err := NewProtectedProcessor(config); err == nil {
			t.Fatal("missing/ambiguous protected operation accepted")
		}
	}
}

// This store is an in-process test double, never a durable production retry or
// idempotency implementation. Its per-delivery lease serializes test consumers.
type protectedTransportStore struct {
	mu     sync.Mutex
	states map[DeliveryKey]State
}
type protectedTransportLease struct {
	store *protectedTransportStore
	key   DeliveryKey
}

func (s *protectedTransportStore) Acquire(_ context.Context, key DeliveryKey) (Lease, error) {
	s.mu.Lock()
	if s.states == nil {
		s.states = make(map[DeliveryKey]State)
	}
	return &protectedTransportLease{store: s, key: key}, nil
}
func (l *protectedTransportLease) Load(context.Context) (State, error) {
	return l.store.states[l.key], nil
}
func (l *protectedTransportLease) Save(_ context.Context, state State) error {
	l.store.states[l.key] = state
	return nil
}
func (l *protectedTransportLease) Release(context.Context) error { l.store.mu.Unlock(); return nil }

func TestProtectedConsumerCommittedACKFailureAndDuplicate(t *testing.T) {
	f := newProtectedFixture(t)
	broker := &protectedBroker{ackErr: errors.New("redis credential=raw-error-secret")}
	producer, err := NewProducer(ProducerConfig{PEP: f.pep, Schema: f.schema, Broker: broker, Audit: f.pep.Audit})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Enqueue(f.ctx, f.request, "fixture-worker", f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(ConsumerConfig{Broker: broker, Schema: f.schema, Processor: f.processor(t), Store: &protectedTransportStore{}, Retry: RetryPolicy{MaxAttempts: 2, Backoff: func(uint32) time.Duration { return 0 }}, Audit: f.pep.Audit})
	if err != nil {
		t.Fatal(err)
	}
	delivery := Delivery{ID: "1-0", Fields: broker.fields}
	if _, err := consumer.Handle(f.worker, delivery); !errors.Is(err, ErrACK) {
		t.Fatalf("ACK failure = %v", err)
	}
	if f.boundary.executions != 1 || !f.boundary.approval.Consumed {
		t.Fatal("ACK failure undid committed protected operation")
	}
	broker.ackErr = nil
	for range 2 {
		result, err := consumer.Handle(f.worker, delivery)
		if err != nil || result.Outcome != Acknowledged || f.boundary.executions != 1 {
			t.Fatalf("completed duplicate = %+v,%v", result, err)
		}
	}
	// A new transport entry is not a new business approval. It reaches the PEP
	// and is permanently denied rather than resetting consumed state.
	result, err := consumer.Handle(f.worker, Delivery{ID: "2-0", Fields: broker.fields})
	if err != nil || result.Outcome != DeadLettered || result.Failure != (Classification{Permanent, Denied}) || f.boundary.executions != 1 {
		t.Fatalf("new delivery reused approval: %+v,%v", result, err)
	}
	if strings.Contains(f.log.String(), "raw-error-secret") {
		t.Fatal("raw Redis error leaked")
	}
}

func TestProtectedConsumerClaimDoesNotGrantWorkerAuthority(t *testing.T) {
	f := newProtectedFixture(t)
	m := f.metadata(t)
	fields, err := f.schema.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	broker := &protectedBroker{fields: fields, pending: []Pending{{ID: "1-0", Consumer: "old-consumer", Idle: time.Second, Deliveries: 9999}}}
	consumer, err := NewConsumer(ConsumerConfig{Broker: broker, Schema: f.schema, Processor: f.processor(t), Store: &protectedTransportStore{}, Retry: RetryPolicy{MaxAttempts: 2, Backoff: func(uint32) time.Duration { return 0 }}, Audit: f.pep.Audit})
	if err != nil {
		t.Fatal(err)
	}
	wrongWorker := authorization.WithVerifiedWorker(context.Background(), "claimed-consumer")
	results, err := consumer.Recover(wrongWorker, 1, time.Millisecond)
	if err != nil || len(results) != 1 || results[0].Outcome != DeadLettered || results[0].Failure != (Classification{Permanent, Denied}) || f.boundary.executions != 0 || f.boundary.approval.Consumed {
		t.Fatalf("claim granted authority: %+v,%v", results, err)
	}
}

func TestProtectedCompletedRecoveryPDPDependencyIsBounded(t *testing.T) {
	f := newProtectedFixture(t)
	m := f.metadata(t)
	fields, err := f.schema.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	broker := &protectedBroker{fields: fields, ackErr: ErrUnavailable}
	consumer, err := NewConsumer(ConsumerConfig{Broker: broker, Schema: f.schema, Processor: f.processor(t), Store: &protectedTransportStore{}, Retry: RetryPolicy{MaxAttempts: 3, Backoff: func(uint32) time.Duration { return time.Second }}, Audit: f.pep.Audit, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	delivery := Delivery{ID: "1-0", Fields: fields}
	if _, err := consumer.Handle(f.worker, delivery); !errors.Is(err, ErrACK) {
		t.Fatal("expected committed operation and failed ACK")
	}
	broker.ackErr = nil
	pdpCalls := 0
	f.pep.Policy = protectedPolicy(func(context.Context, authorization.Execution) (authorization.Decision, error) {
		pdpCalls++
		return authorization.Decision{}, errors.New("PDP credential=never-log")
	})
	if r, err := consumer.Handle(f.worker, delivery); !errors.Is(err, ErrDeferred) || r.Attempts != 2 {
		t.Fatalf("first recovery: %+v %v", r, err)
	}
	if _, err := consumer.Handle(f.worker, delivery); !errors.Is(err, ErrDeferred) || pdpCalls != 1 {
		t.Fatal("fresh PDP bypassed backoff")
	}
	f.now = f.now.Add(time.Second)
	r, err := consumer.Handle(f.worker, delivery)
	if err != nil || r.Outcome != DeadLettered || r.Attempts != 3 || r.Failure != (Classification{Transient, Dependency}) || pdpCalls != 2 {
		t.Fatalf("bounded recovery: %+v %v", r, err)
	}
	if f.boundary.executions != 1 || !f.boundary.approval.Consumed || strings.Contains(f.log.String(), "never-log") {
		t.Fatal("recovery changed protected completion or leaked dependency")
	}
}
