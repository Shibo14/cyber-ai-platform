package encryption

import (
	"context"
	"crypto/subtle"
	"strings"

	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantidentity"
)

type Service struct {
	config  Config
	suiteID string
}

func New(config Config) (*Service, error) {
	if config.PEP == nil || config.KMS == nil || config.Cipher == nil || config.Keys == nil ||
		config.Audit == nil || strings.TrimSpace(config.ProfileID) == "" {
		return nil, ErrDependency
	}
	id := config.Cipher.ID()
	if strings.TrimSpace(id) == "" {
		return nil, ErrDependency
	}
	return &Service{config: config, suiteID: id}, nil
}

func (s *Service) binding(ctx context.Context, e authorization.Execution) (Binding, error) {
	identity, ok := tenantidentity.FromContext(ctx)
	tenant, err := tenantidentity.ParseTenantID(string(identity.TenantID))
	if !ok || err != nil || tenant != identity.TenantID || tenant != e.TenantID ||
		strings.TrimSpace(identity.PrincipalID) == "" || identity.PrincipalID != string(e.Subject) {
		return Binding{}, ErrDenied
	}
	return Binding{TenantID: tenant, ProfileID: s.config.ProfileID, SuiteID: s.suiteID}, nil
}

func cloneHeader(h Header) Header { h.WrappedDEK = append([]byte(nil), h.WrappedDEK...); return h }
func clonePayload(p Payload) Payload {
	return Payload{Ciphertext: append([]byte(nil), p.Ciphertext...), Nonce: append([]byte(nil), p.Nonce...), Tag: append([]byte(nil), p.Tag...)}
}
func cloneEnvelope(e Envelope) Envelope {
	return Envelope{Header: cloneHeader(e.Header), Payload: clonePayload(e.Payload)}
}
func wipePayload(p Payload)   { clear(p.Ciphertext); clear(p.Nonce); clear(p.Tag) }
func wipeEnvelope(e Envelope) { clear(e.Header.WrappedDEK); wipePayload(e.Payload) }

func (s *Service) validEnvelope(e Envelope, binding Binding) bool {
	return e.Header.Binding == binding && strings.TrimSpace(e.Header.KeyReference) != "" &&
		len(e.Header.WrappedDEK) > 0 && s.config.Cipher.ValidatePayload(e.Payload)
}

func (s *Service) emit(e authorization.Execution, action, outcome string, err error) error {
	// Fixed classifications only; never errors, plaintext, keys, envelope blobs,
	// stored metadata/key references or SDK request/response objects.
	if s.config.Audit.Emit(map[string]any{
		"event": "kms_access", "action": action, "outcome": outcome, "failure_class": failureClass(err),
		"tenant_id": string(e.TenantID), "actor_id": string(e.Actor), "subject_id": string(e.Subject),
		"correlation_id": e.CorrelationID,
	}) != nil {
		return ErrDependency
	}
	return nil
}

func (s *Service) kmsCall(ctx context.Context, e authorization.Execution, action string, call func() ([]byte, error), valid func([]byte) bool) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, kmsError(ctx.Err())
	}
	if err := s.emit(e, action, "attempted", nil); err != nil {
		return nil, err
	}
	data, rawErr := call()
	var err error
	if rawErr != nil {
		err = kmsError(rawErr)
	} else if ctx.Err() != nil {
		err = kmsError(ctx.Err())
	} else if !valid(data) {
		err = ErrCorruptResponse
	}
	outcome := "allowed"
	if err != nil {
		outcome = "failed"
	}
	if auditErr := s.emit(e, action, outcome, err); auditErr != nil {
		err = auditErr
	}
	if err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

func (s *Service) seal(ctx context.Context, e authorization.Execution, binding Binding, keyRef string, plaintext []byte) (Envelope, error) {
	key, err := s.config.Cipher.GenerateKey(ctx)
	defer clear(key)
	if err != nil {
		return Envelope{}, ErrDependency
	}
	if !s.config.Cipher.ValidateKey(key) {
		return Envelope{}, ErrCorruptResponse
	}
	wrapped, err := s.kmsCall(ctx, e, "kms_wrap", func() ([]byte, error) {
		return s.config.KMS.Wrap(ctx, keyRef, key, binding)
	}, func(b []byte) bool { return len(b) > 0 && subtle.ConstantTimeCompare(key, b) != 1 })
	if err != nil {
		return Envelope{}, err
	}
	defer clear(wrapped)
	// Verify even a non-empty corrupt wrapping response before returning anything
	// persistable. This is outside all DB txs; KEKs never leave the KMS adapter.
	verified, err := s.kmsCall(ctx, e, "kms_unwrap", func() ([]byte, error) {
		return s.config.KMS.Unwrap(ctx, keyRef, wrapped, binding)
	}, func(b []byte) bool { return s.config.Cipher.ValidateKey(b) && subtle.ConstantTimeCompare(key, b) == 1 })
	clear(verified)
	if err != nil {
		return Envelope{}, err
	}
	header := Header{Binding: binding, KeyReference: keyRef, WrappedDEK: append([]byte(nil), wrapped...)}
	payload, err := s.config.Cipher.Seal(ctx, key, plaintext, cloneHeader(header))
	if err != nil || ctx.Err() != nil || !s.config.Cipher.ValidatePayload(payload) {
		clear(header.WrappedDEK)
		wipePayload(payload)
		return Envelope{}, ErrDependency
	}
	return Envelope{Header: header, Payload: payload}, nil
}

func (s *Service) open(ctx context.Context, e authorization.Execution, envelope Envelope, binding Binding) ([]byte, error) {
	if !s.validEnvelope(envelope, binding) || !s.config.Keys.AllowDecryptionKey(e, envelope.Header.KeyReference) {
		return nil, ErrDenied
	}
	key, err := s.kmsCall(ctx, e, "kms_unwrap", func() ([]byte, error) {
		return s.config.KMS.Unwrap(ctx, envelope.Header.KeyReference, append([]byte(nil), envelope.Header.WrappedDEK...), binding)
	}, s.config.Cipher.ValidateKey)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.config.Cipher.Open(ctx, key, clonePayload(envelope.Payload), cloneHeader(envelope.Header))
	if err != nil || ctx.Err() != nil {
		clear(plaintext)
		return nil, ErrDenied
	}
	return plaintext, nil
}
