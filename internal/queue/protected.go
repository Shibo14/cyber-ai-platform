package queue

import (
	"context"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/encryption"
)

// ToolResolver is trusted server wiring for one already-approved tool. It must
// bind its actual arguments to request.Operation, never decode authority or a
// payload from Redis fields. Tool database access uses the PEP-provided tx.
// Resolution only constructs/selects an adapter: no tenant-owned storage reads,
// KMS calls, plaintext release, publication or irreversible effects occur here.
type ToolResolver func(context.Context, authorization.WorkerRequest) (authorization.Tool, error)

// DecryptResolver selects an existing CYB-14 service and tenant-owned storage.
// This is trusted application wiring, not a queue-supplied callback. The service
// must use this processor's PEP and authoritative repositories. Storage obeys
// CYB-14 Operation/LockState/CheckState binding and the supplied CYB-12 tx.
// Resolution selects adapters only, with no payload/tenant-owned storage access,
// KMS invocation, plaintext handling or side effects before the PEP boundary.
type DecryptResolver func(context.Context, authorization.WorkerRequest) (*encryption.Service, encryption.Storage, error)

type ProtectedConfig struct {
	PEP     *authorization.PEP
	Tool    ToolResolver
	Decrypt DecryptResolver
}

// ProtectedProcessor admits one protected operation per delegation. Tool and
// decrypt modes are exclusive: no separate post-decrypt action callback exists.
// Composite workflows/approval taxonomy remain TBD. Successful decrypt results
// are cleared and discarded; they never enter queue state, messages or audit.
type ProtectedProcessor struct{ config ProtectedConfig }

func NewProtectedProcessor(config ProtectedConfig) (*ProtectedProcessor, error) {
	if config.PEP == nil || config.PEP.Audit == nil || (config.Tool == nil) == (config.Decrypt == nil) {
		return nil, ErrConfiguration
	}
	return &ProtectedProcessor{config: config}, nil
}

func (p *ProtectedProcessor) VerifyWorker(ctx context.Context) error {
	if err := p.config.PEP.VerifyWorker(ctx); err != nil {
		return Classify(err)
	}
	return nil
}

// Authorize is also required before ACK-only duplicate recovery. It performs
// fresh actor AND subject PDP, without consuming an already-executed approval.
func (p *ProtectedProcessor) Authorize(ctx context.Context, metadata Metadata) error {
	_, err := p.config.PEP.ResolveWorker(ctx, metadata.Reference)
	if err != nil {
		return Classify(err)
	}
	return nil
}

func (p *ProtectedProcessor) Process(ctx context.Context, metadata Metadata) error {
	request, err := p.config.PEP.ResolveWorker(ctx, metadata.Reference)
	if err != nil {
		return Classify(err)
	}
	if p.config.Tool != nil {
		tool, err := p.config.Tool(ctx, request)
		if err != nil {
			return Classify(err)
		}
		if tool == nil {
			return Classify(ErrDependency)
		}
		// Re-resolves delegation and performs execution-time PDP, one-shot
		// approval consumption and resource-state locking/CAS in WithTenantTx.
		if err := p.config.PEP.ExecuteWorker(ctx, request, tool); err != nil {
			return Classify(err)
		}
		return nil
	}
	service, storage, err := p.config.Decrypt(ctx, request)
	if err != nil {
		return Classify(err)
	}
	if service == nil || storage == nil {
		return Classify(ErrDependency)
	}
	plaintext, err := service.DecryptWorker(ctx, request, storage)
	defer clear(plaintext)
	if err != nil {
		return Classify(err)
	}
	return nil
}

type ProducerConfig struct {
	PEP    *authorization.PEP
	Schema *Schema
	Broker Broker
	Audit  *audit.Logger
}
type Producer struct{ config ProducerConfig }

func NewProducer(config ProducerConfig) (*Producer, error) {
	if config.PEP == nil || config.PEP.Audit == nil || config.Schema == nil || config.Broker == nil || config.Audit == nil {
		return nil, ErrConfiguration
	}
	return &Producer{config: config}, nil
}

// Enqueue accepts no payload/tenant/subject fields. Trusted dispatch code selects
// the exact request, worker and validity; Delegate requires authenticated user
// context and independently authorizes the original actor/subject and worker.
// Payload persistence must already use CYB-14/CYB-12 boundaries. No atomic
// PostgreSQL+Redis publication or production outbox policy is implied here.
// A publish/audit failure may follow delegation creation or Redis acceptance:
// reconciliation remains the caller's approved production workflow decision.
func (p *Producer) Enqueue(ctx context.Context, request authorization.Request, worker authorization.ActorPrincipal, expires time.Time) (string, error) {
	reference, err := p.config.PEP.Delegate(ctx, request, worker, expires)
	var id string
	if err == nil {
		var fields Fields
		fields, err = p.config.Schema.Encode(p.config.Schema.Metadata(reference))
		if err == nil {
			id, err = p.config.Broker.Publish(ctx, fields)
			if err == nil && id == "" {
				err = ErrProtocol
			}
		}
	}
	outcome := "allowed"
	class := "none"
	if err != nil {
		outcome = "failed"
		class = string(Classify(err).Class)
	}
	if auditErr := p.config.Audit.Emit(map[string]any{"event": "queue_enqueue", "outcome": outcome, "failure_class": class}); auditErr != nil {
		return "", ErrAudit
	}
	if err != nil {
		return "", Classify(err)
	}
	return id, nil
}
