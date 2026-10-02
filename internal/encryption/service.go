package encryption

import (
	"context"
	"errors"
	"strings"

	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantdb"
)

// Encrypt/Decrypt are protected operations. Their prepared buffers are released
// only after the existing final PEP transaction AND its audit result succeed.
// Production resource/permission/approval workflows remain unselected.
func (s *Service) Encrypt(ctx context.Context, request authorization.Request, storage Storage, plaintext []byte) (Envelope, error) {
	p := s.preparation(Encrypt, storage, plaintext)
	defer p.discard()
	err := s.config.PEP.ExecutePrepared(ctx, request, p)
	if err != nil {
		return Envelope{}, p.resultError(err)
	}
	return cloneEnvelope(p.envelope), nil
}

func (s *Service) Decrypt(ctx context.Context, request authorization.Request, storage Storage) ([]byte, error) {
	p := s.preparation(Decrypt, storage, nil)
	defer p.discard()
	err := s.config.PEP.ExecutePrepared(ctx, request, p)
	if err != nil {
		return nil, p.resultError(err)
	}
	return append([]byte(nil), p.plaintext...), nil
}

func (s *Service) EncryptWorker(ctx context.Context, request authorization.WorkerRequest, storage Storage, plaintext []byte) (Envelope, error) {
	p := s.preparation(Encrypt, storage, plaintext)
	defer p.discard()
	err := s.config.PEP.ExecuteWorkerPrepared(ctx, request, p)
	if err != nil {
		return Envelope{}, p.resultError(err)
	}
	return cloneEnvelope(p.envelope), nil
}

func (s *Service) DecryptWorker(ctx context.Context, request authorization.WorkerRequest, storage Storage) ([]byte, error) {
	p := s.preparation(Decrypt, storage, nil)
	defer p.discard()
	err := s.config.PEP.ExecuteWorkerPrepared(ctx, request, p)
	if err != nil {
		return nil, p.resultError(err)
	}
	return append([]byte(nil), p.plaintext...), nil
}

type preparation struct {
	service   *Service
	mode      Mode
	storage   Storage
	input     []byte
	binding   Binding
	keyRef    string
	envelope  Envelope
	plaintext []byte
	failure   error
}

func (s *Service) preparation(mode Mode, storage Storage, plaintext []byte) *preparation {
	return &preparation{service: s, mode: mode, storage: storage, input: append([]byte(nil), plaintext...)}
}

func (p *preparation) discard() { clear(p.input); clear(p.plaintext); wipeEnvelope(p.envelope) }

func (p *preparation) resultError(err error) error {
	if errors.Is(err, authorization.ErrDenied) || errors.Is(err, authorization.ErrState) {
		return ErrDenied
	}
	if p.failure != nil {
		return p.failure
	}
	return ErrDependency
}

func (p *preparation) LockState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (string, error) {
	if p.storage == nil {
		return "", authorization.ErrDependency
	}
	binding, err := p.service.binding(ctx, e)
	if err != nil {
		return "", authorization.ErrDenied
	}
	p.binding = binding
	state, err := p.storage.LockState(ctx, tx, e)
	if err != nil {
		return "", err
	}
	if p.mode == Encrypt {
		p.keyRef, err = p.service.config.Keys.EncryptionKey(e)
		if err != nil || strings.TrimSpace(p.keyRef) == "" {
			return "", authorization.ErrDependency
		}
	} else {
		envelope, err := p.storage.Load(ctx, tx, e)
		if err != nil {
			return "", err
		}
		p.envelope = cloneEnvelope(envelope)
		p.keyRef = envelope.Header.KeyReference
		if !p.service.validEnvelope(p.envelope, binding) || !p.service.config.Keys.AllowDecryptionKey(e, p.keyRef) {
			return "", authorization.ErrDenied
		}
	}
	// Pass a private plaintext copy: an adapter cannot mutate the actual input
	// between approval fingerprint calculation and crypto preparation.
	input := append([]byte(nil), p.input...)
	defer clear(input)
	operation, err := p.storage.Operation(e, Inputs{Mode: p.mode, Plaintext: input, Binding: binding, KeyReference: p.keyRef})
	if err != nil {
		return "", err
	}
	if operation != e.Operation {
		return "", authorization.ErrDenied
	}
	return state, nil
}

func (p *preparation) Prepare(ctx context.Context, e authorization.Execution) (authorization.Tool, error) {
	binding, err := p.service.binding(ctx, e)
	if err != nil || binding != p.binding {
		return nil, authorization.ErrDenied
	}
	if p.mode == Encrypt {
		p.envelope, p.failure = p.service.seal(ctx, e, binding, p.keyRef, p.input)
	} else {
		p.plaintext, p.failure = p.service.open(ctx, e, p.envelope, binding)
	}
	if p.failure != nil {
		return nil, authorization.ErrDependency
	}
	return finalTool{p}, nil
}

type finalTool struct{ prepared *preparation }

func (tool finalTool) LockState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution) (string, error) {
	return tool.prepared.storage.LockState(ctx, tx, e)
}

func (tool finalTool) ExecuteIfState(ctx context.Context, tx tenantdb.TenantTx, e authorization.Execution, expected string) error {
	p := tool.prepared
	if p.mode == Encrypt {
		return p.storage.StoreIfState(ctx, tx, e, expected, cloneEnvelope(p.envelope))
	}
	return p.storage.CheckState(ctx, tx, e, expected)
}
