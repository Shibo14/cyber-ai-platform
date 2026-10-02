package encryption

// All algorithms, JSON AAD, key sizes, key IDs, action names and repositories in
// this file are TEST FIXTURES. They do not select production crypto or encoding.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

const tenantA tenantidentity.TenantID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const tenantB tenantidentity.TenantID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

type testCipher struct {
	wrongAAD    bool
	openError   bool
	generated   [][]byte
	encodedKeys []string
	opened      [][]byte
}

func (*testCipher) ID() string { return "test-only-aead" }
func (c *testCipher) GenerateKey(context.Context) ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	c.generated = append(c.generated, key)
	c.encodedKeys = append(c.encodedKeys, hex.EncodeToString(key))
	return key, err
}
func (*testCipher) ValidateKey(key []byte) bool    { return len(key) == 32 }
func (*testCipher) ValidatePayload(p Payload) bool { return len(p.Nonce) == 12 && len(p.Tag) == 16 }
func fixtureAAD(h Header) []byte                   { data, _ := json.Marshal(h); return data }
func fixtureAEAD(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	result, _ := cipher.NewGCM(block)
	return result
}
func (c *testCipher) Seal(_ context.Context, key, plaintext []byte, header Header) (Payload, error) {
	aead := fixtureAEAD(key)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Payload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, fixtureAAD(header))
	return Payload{Nonce: nonce, Ciphertext: sealed[:len(sealed)-aead.Overhead()], Tag: sealed[len(sealed)-aead.Overhead():]}, nil
}
func (c *testCipher) Open(_ context.Context, key []byte, payload Payload, header Header) ([]byte, error) {
	if c.wrongAAD {
		header.Binding.ProfileID += "wrong"
	}
	if c.openError {
		partial := []byte("partial-plaintext-secret")
		c.opened = append(c.opened, partial)
		return partial, errors.New("SDK credential=never-log-sdk")
	}
	sealed := append(append([]byte(nil), payload.Ciphertext...), payload.Tag...)
	return fixtureAEAD(key).Open(nil, payload.Nonce, sealed, fixtureAAD(header))
}

type testKMS struct {
	kek           []byte
	calls         int
	insideTxCalls int
	inTx          *bool
	failure       error
	corrupt       string
	wrongContext  bool
	keys          [][]byte
	onCall        func()
}

func fixtureKMS(inTx *bool) *testKMS {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &testKMS{kek: key, inTx: inTx}
}
func (k *testKMS) before() error {
	k.calls++
	if k.inTx != nil && *k.inTx {
		k.insideTxCalls++
		return errors.New("KMS was invoked inside a tenant tx")
	}
	if k.onCall != nil {
		k.onCall()
	}
	return k.failure
}
func fixtureKMSAAD(ref string, b Binding) []byte {
	data, _ := json.Marshal(struct {
		Key     string
		Binding Binding
	}{ref, b})
	return data
}
func (k *testKMS) Wrap(_ context.Context, ref string, key []byte, binding Binding) ([]byte, error) {
	if err := k.before(); err != nil {
		return []byte("partial-sdk-secret"), err
	}
	if k.corrupt == "empty_wrap" {
		return nil, nil
	}
	if k.corrupt == "garbage_wrap" {
		return []byte("nonempty-corrupt-response"), nil
	}
	if k.corrupt == "plaintext_wrap" {
		return append([]byte(nil), key...), nil
	}
	aead := fixtureAEAD(k.kek)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, key, fixtureKMSAAD(ref, binding)), nil
}
func (k *testKMS) Unwrap(_ context.Context, ref string, wrapped []byte, binding Binding) ([]byte, error) {
	if err := k.before(); err != nil {
		return []byte("partial-DEK-secret"), err
	}
	if k.corrupt == "short_key" {
		key := []byte("invalid-key-secret")
		k.keys = append(k.keys, key)
		return key, nil
	}
	if k.corrupt == "wrong_key" {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		k.keys = append(k.keys, key)
		return key, nil
	}
	if k.wrongContext {
		binding.TenantID = tenantB
	}
	aead := fixtureAEAD(k.kek)
	if len(wrapped) < aead.NonceSize()+aead.Overhead() {
		return nil, KMSFailure{Kind: CorruptResponse}
	}
	key, err := aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], fixtureKMSAAD(ref, binding))
	if err != nil {
		return nil, KMSFailure{Kind: Denied}
	}
	k.keys = append(k.keys, key)
	return key, nil
}

type testKeys struct{}

func (testKeys) EncryptionKey(authorization.Execution) (string, error) { return "test-shared-key", nil }
func (testKeys) AllowDecryptionKey(_ authorization.Execution, ref string) bool {
	return ref == "test-shared-key"
}

type policyFunc func(context.Context, authorization.Execution) (authorization.Decision, error)

func (f policyFunc) Evaluate(ctx context.Context, e authorization.Execution) (authorization.Decision, error) {
	return f(ctx, e)
}

type testBoundary struct {
	inTx       bool
	approval   authorization.Approval
	failCommit bool
	storage    *testStorage
}

func (b *testBoundary) WithTenantTx(ctx context.Context, fn func(tenantdb.TenantTx) error) error {
	if _, ok := tenantidentity.FromContext(ctx); !ok {
		return tenantdb.ErrAuthenticatedIdentityRequired
	}
	oldApproval, oldEnvelope, oldStores := b.approval, cloneEnvelope(b.storage.envelope), b.storage.stores
	b.inTx = true
	defer func() { b.inTx = false }()
	err := fn(nil)
	if err == nil && b.failCommit {
		err = errors.New("database commit failed credential=never-log-db")
	}
	if err != nil {
		b.approval = oldApproval
		b.storage.envelope = oldEnvelope
		b.storage.stores = oldStores
	}
	return err
}

type testApprovals struct{ boundary *testBoundary }

func (s testApprovals) Load(context.Context, tenantdb.TenantTx, string) (authorization.Approval, error) {
	return s.boundary.approval, nil
}
func (s testApprovals) Consume(context.Context, tenantdb.TenantTx, string) (bool, error) {
	if s.boundary.approval.Consumed {
		return false, nil
	}
	s.boundary.approval.Consumed = true
	return true, nil
}

type testDelegations struct {
	records map[string]authorization.Delegation
}

func (s *testDelegations) Create(_ context.Context, d authorization.Delegation) error {
	if _, exists := s.records[d.ID]; exists {
		return errors.New("duplicate delegation ID")
	}
	s.records[d.ID] = d
	return nil
}
func (s *testDelegations) Load(_ context.Context, id string) (authorization.Delegation, error) {
	d, ok := s.records[id]
	if !ok {
		return authorization.Delegation{}, errors.New("unknown reference")
	}
	return d, nil
}

type testStorage struct {
	state           string
	envelope        Envelope
	stores          int
	failWrite       bool
	finalCASFailure bool
	lastTenant      tenantidentity.TenantID
}

func fixtureOperation(e authorization.Execution, in Inputs) authorization.Operation {
	data, _ := json.Marshal(in)
	sum := sha256.Sum256(data)
	action := "test:encrypt"
	if in.Mode == Decrypt {
		action = "test:decrypt"
	}
	return authorization.Operation{Action: action, ResourceID: "test:object", InputFingerprint: hex.EncodeToString(sum[:])}
}
func (*testStorage) Operation(e authorization.Execution, in Inputs) (authorization.Operation, error) {
	return fixtureOperation(e, in), nil
}
func (s *testStorage) LockState(ctx context.Context, _ tenantdb.TenantTx, e authorization.Execution) (string, error) {
	id, ok := tenantidentity.FromContext(ctx)
	if !ok || id.TenantID != e.TenantID {
		return "", authorization.ErrDenied
	}
	s.lastTenant = id.TenantID
	return s.state, nil
}
func (s *testStorage) Load(context.Context, tenantdb.TenantTx, authorization.Execution) (Envelope, error) {
	return cloneEnvelope(s.envelope), nil
}
func (s *testStorage) CheckState(_ context.Context, _ tenantdb.TenantTx, _ authorization.Execution, expected string) error {
	if s.state != expected || s.finalCASFailure {
		return authorization.ErrState
	}
	return nil
}
func (s *testStorage) StoreIfState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string, envelope Envelope) error {
	if err := s.CheckState(ctx, tx, e, expected); err != nil {
		return err
	}
	s.envelope = cloneEnvelope(envelope)
	s.stores++
	if s.failWrite {
		return errors.New("storage failed after write")
	}
	return nil
}

type fixture struct {
	s            *Service
	p            *authorization.PEP
	store        *testStorage
	boundary     *testBoundary
	kms          *testKMS
	cipher       *testCipher
	sink         bytes.Buffer
	ctx          context.Context
	now          time.Time
	nextApproval int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: &testStorage{state: "test-state"}, cipher: &testCipher{}, now: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	f.boundary = &testBoundary{storage: f.store}
	f.kms = fixtureKMS(&f.boundary.inTx)
	logger := audit.New(&f.sink, "event", "action", "outcome", "failure_class", "tenant_id", "actor_id", "subject_id", "correlation_id", "resource_id")
	f.p = &authorization.PEP{DB: f.boundary, Approvals: testApprovals{f.boundary}, Audit: logger,
		Delegations: &testDelegations{records: make(map[string]authorization.Delegation)},
		Policy: policyFunc(func(context.Context, authorization.Execution) (authorization.Decision, error) {
			return authorization.Decision{ActorAllowed: true, SubjectAllowed: true}, nil
		}), Now: func() time.Time { return f.now }}
	var err error
	f.s, err = New(Config{PEP: f.p, KMS: f.kms, Cipher: f.cipher, Keys: testKeys{}, Audit: logger, ProfileID: "test-only-profile"})
	if err != nil {
		t.Fatal(err)
	}
	f.ctx = authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(), tenantidentity.Identity{TenantID: tenantA, PrincipalID: "test-human"}), "test-api")
	return f
}
func (f *fixture) request(mode Mode, plaintext []byte, tenant tenantidentity.TenantID) authorization.Request {
	b := Binding{TenantID: tenant, ProfileID: "test-only-profile", SuiteID: f.cipher.ID()}
	e := authorization.Execution{TenantID: tenant, Subject: "test-human", Actor: "test-api"}
	op := fixtureOperation(e, Inputs{Mode: mode, Plaintext: plaintext, Binding: b, KeyReference: "test-shared-key"})
	f.nextApproval++
	r := authorization.Request{Operation: op, ApprovalID: "test-approval-" + strconv.Itoa(f.nextApproval), CorrelationID: "test-correlation"}
	f.boundary.approval = authorization.Approval{ID: r.ApprovalID, TenantID: tenant, Subject: e.Subject, Operation: op, ResourceState: f.store.state, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}
	return r
}
func (f *fixture) encrypted(t *testing.T, plaintext []byte) Envelope {
	t.Helper()
	envelope, err := f.s.Encrypt(f.ctx, f.request(Encrypt, plaintext, tenantA), f.store, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
func assertDenied(t *testing.T, plaintext []byte, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) || plaintext != nil {
		t.Fatalf("want denial and no plaintext, got bytes=%d error=%v", len(plaintext), err)
	}
}
