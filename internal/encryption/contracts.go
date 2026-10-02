// Package encryption supplies a provider-, algorithm- and wire-format-neutral
// CYB-14 core. There are no production cryptographic adapters or default suite.
package encryption

import (
	"context"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

// Binding must be authenticated by KMS wrapping and unwrapping. Provider field
// names/encoding are the future adapter's responsibility, not caller input.
// TenantID always comes from verified identity/delegation. It is not secret.
type Binding struct {
	TenantID  tenantidentity.TenantID
	ProfileID string
	SuiteID   string
}

// KMS never exports KEKs. Wrap/Unwrap must enforce the exact key reference and
// Binding, validate provider responses, respect context cancellation, and never
// log key material or raw requests/responses. Only an encrypted DEK is durable.
type KMS interface {
	Wrap(context.Context, string, []byte, Binding) ([]byte, error)
	Unwrap(context.Context, string, []byte, Binding) ([]byte, error)
}

// Header is the complete security-critical AAD input. It is an in-memory
// contract, NOT a selected serialization format. Suite adapters must encode
// every field unambiguously and authenticate every field, including WrappedDEK.
// No object/version binding is added: that remains deferred.
type Header struct {
	Binding      Binding
	KeyReference string
	WrappedDEK   []byte
}

// Payload representation and nonce/tag sizes belong to the injected suite.
// No algorithm or final storage/wire encoding is selected by these types.
type Payload struct {
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
}

type Envelope struct {
	Header  Header
	Payload Payload
}

// CipherSuite must use authenticated encryption, secure key generation and the
// algorithm's nonce rules. Open authenticates all Header/Payload fields before
// returning plaintext. ValidateKey/ValidatePayload reject malformed responses.
// Adapters must not retain, persist, stringify or log plaintext/key buffers.
type CipherSuite interface {
	ID() string
	GenerateKey(context.Context) ([]byte, error)
	ValidateKey([]byte) bool
	ValidatePayload(Payload) bool
	Seal(context.Context, []byte, []byte, Header) (Payload, error)
	Open(context.Context, []byte, Payload, Header) ([]byte, error)
}

// Keys is trusted configuration/policy, not a caller-selected key reference.
// These methods must not invoke KMS or perform external side effects. Key
// hierarchy, historical key availability and rotation policy remain TBD.
type Keys interface {
	EncryptionKey(authorization.Execution) (string, error)
	AllowDecryptionKey(authorization.Execution, string) bool
}

type Mode uint8

const (
	Encrypt Mode = iota + 1
	Decrypt
)

// Inputs lets the trusted storage/tool adapter recompute the exact operation
// fingerprint over all execution-affecting inputs; never trust its request copy.
// Plaintext exists only for this in-process calculation, never for persistence.
type Inputs struct {
	Mode         Mode
	Plaintext    []byte
	Binding      Binding
	KeyReference string
}

// Storage is an adapter for a server-selected resource/tool. All data access
// uses the supplied CYB-12 tx. Operation must compute the actual action/resource/
// input binding. LockState and StoreIfState/CheckState obey CYB-13 lock/CAS rules.
// No KMS calls occur in these methods. Never write plaintext, DEKs or raw errors.
// CheckState is a transactional precondition, not an object-binding crypto rule.
type Storage interface {
	Operation(authorization.Execution, Inputs) (authorization.Operation, error)
	LockState(context.Context, tenantdb.TenantTx, authorization.Execution) (string, error)
	Load(context.Context, tenantdb.TenantTx, authorization.Execution) (Envelope, error)
	StoreIfState(context.Context, tenantdb.TenantTx, authorization.Execution, string, Envelope) error
	CheckState(context.Context, tenantdb.TenantTx, authorization.Execution, string) error
}

// Config deliberately has no defaults for provider, cipher, profile or keys.
// Production implementations/policy and serialization need their open decisions.
type Config struct {
	PEP       *authorization.PEP
	KMS       KMS
	Cipher    CipherSuite
	Keys      Keys
	Audit     *audit.Logger
	ProfileID string
}
