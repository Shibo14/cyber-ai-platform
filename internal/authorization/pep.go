package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

// Decision requires independent workload AND subject authorization. A worker's
// infrastructure privileges can never substitute for SubjectAllowed.
type Decision struct {
	ActorAllowed   bool
	SubjectAllowed bool
}

type PolicyEvaluator interface {
	Evaluate(context.Context, Execution) (Decision, error)
}

// ApprovalRepository implementations must load/consume using this exact tenant
// transaction. Consume is an atomic unconsumed -> consumed transition and returns
// false on reuse. It must happen before Tool and roll back with the operation.
// IDs are insert-only, never recycled or overwritten after consumption.
type ApprovalRepository interface {
	Load(context.Context, tenantdb.TenantTx, string) (Approval, error)
	Consume(context.Context, tenantdb.TenantTx, string) (bool, error)
}

type DelegationRepository interface {
	// Create must insert only, reject duplicate IDs, and persist an immutable copy.
	Create(context.Context, Delegation) error
	// Load reads authoritative state, never decoded client/queue authority fields.
	Load(context.Context, string) (Delegation, error)
}

type TenantBoundary interface {
	WithTenantTx(context.Context, func(tenantdb.TenantTx) error) error
}

// Tool is a trusted adapter for a specific server-approved tool. LockState must
// read current state within tx and lock it until completion, or ExecuteIfState
// must enforce an atomic state precondition. Database writes use the SAME tx;
// This transaction path must not execute nontransactional external side effects;
// those need an equivalent atomic approval/precondition/execution boundary.
// ExecuteIfState returns ErrState without changing the object if it changed.
type Tool interface {
	LockState(context.Context, tenantdb.TenantTx, Execution) (string, error)
	ExecuteIfState(context.Context, tenantdb.TenantTx, Execution, string) error
}

// PEP mediates protected operations only: there is no caller-controlled switch
// to turn off approval or delegation. No identity/permission protocol is chosen.
type PEP struct {
	Policy      PolicyEvaluator
	DB          TenantBoundary
	Approvals   ApprovalRepository
	Delegations DelegationRepository
	Audit       *audit.Logger
	// Now is server-supplied; nil uses the server clock, never a request timestamp.
	Now func() time.Time
}

type Request struct {
	Operation     Operation
	CorrelationID string
	ApprovalID    string
}

// WorkerRequest carries an immutable job reference and the intended operation.
// It deliberately has no tenant, actor, subject or permission claims.
type WorkerRequest struct {
	DelegationID  string
	Operation     Operation
	CorrelationID string
}

func (p *PEP) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *PEP) authorize(ctx context.Context, e Execution) error {
	if p.Policy == nil {
		return ErrDependency
	}
	decision, err := p.Policy.Evaluate(ctx, e)
	if err != nil {
		return ErrDependency // never put raw dependency errors in security logs
	}
	if !decision.ActorAllowed || !decision.SubjectAllowed {
		return ErrDenied
	}
	return nil
}

func (p *PEP) Execute(ctx context.Context, request Request, tool Tool) error {
	e, err := identityExecution(ctx, request.Operation, request.CorrelationID)
	if err == nil {
		err = p.execute(ctx, e, request.ApprovalID, nil, tool)
	}
	return p.result(e, err)
}

// ExecuteWorker always reconstructs authority from trusted job state. The
// caller's workload must have been independently verified before this call.
func (p *PEP) ExecuteWorker(ctx context.Context, request WorkerRequest, tool Tool) error {
	d, err := p.workerExecution(ctx, request)
	if err != nil {
		return p.result(Execution{}, err)
	}
	trusted := tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{
		TenantID: d.Execution.TenantID, PrincipalID: string(d.Execution.Subject),
	})
	err = p.execute(trusted, d.Execution, d.ApprovalID, &d, tool)
	return p.result(d.Execution, err)
}

func (p *PEP) workerExecution(ctx context.Context, request WorkerRequest) (Delegation, error) {
	actor, ok := ctx.Value(actorKey{}).(verifiedActor)
	if !ok || !actor.worker || !nonempty(string(actor.id)) || !nonempty(request.DelegationID) {
		return Delegation{}, ErrDenied
	}
	if p.Delegations == nil {
		return Delegation{}, ErrDependency
	}
	d, err := p.Delegations.Load(ctx, request.DelegationID)
	if err != nil {
		return Delegation{}, ErrDependency
	}
	e := d.Execution
	if e.Actor != actor.id || e.Operation != request.Operation || e.CorrelationID != request.CorrelationID ||
		!validDelegation(d, request.DelegationID, e, p.now()) {
		return Delegation{}, ErrDenied
	}
	// Never silently replace an existing trusted identity with a different user.
	if identity, exists := tenantidentity.FromContext(ctx); exists &&
		(identity.TenantID != e.TenantID || SubjectPrincipal(identity.PrincipalID) != e.Subject) {
		return Delegation{}, ErrDenied
	}
	return d, nil
}

func (p *PEP) execute(ctx context.Context, e Execution, approvalID string, d *Delegation, tool Tool) error {
	if p.DB == nil || p.Approvals == nil || p.Audit == nil || tool == nil {
		return ErrDependency
	}
	err := p.DB.WithTenantTx(ctx, func(tx tenantdb.TenantTx) error {
		// Queue admission never bypasses the execution-time PDP decision.
		if err := p.authorize(ctx, e); err != nil {
			return err
		}
		if !nonempty(approvalID) {
			return ErrDenied
		}
		a, err := p.Approvals.Load(ctx, tx, approvalID)
		if err != nil {
			return ErrDependency
		}
		state, err := tool.LockState(ctx, tx, e)
		if err != nil {
			return ErrDependency
		}
		// Check the clock AFTER potentially slow store/state reads.
		if !validApproval(a, approvalID, e, state, p.now()) ||
			(d != nil && !validDelegation(*d, d.ID, e, p.now())) {
			return ErrDenied
		}
		consumed, err := p.Approvals.Consume(ctx, tx, approvalID)
		if err != nil {
			return ErrDependency
		}
		if !consumed {
			return ErrDenied
		}
		// Recheck validity after a potentially blocking atomic consumption.
		if !validPeriod(a.IssuedAt, a.ExpiresAt, p.now()) ||
			(d != nil && !validPeriod(d.IssuedAt, d.ExpiresAt, p.now())) {
			return ErrDenied
		}
		return tool.ExecuteIfState(ctx, tx, e, a.ResourceState)
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrDenied) {
		return ErrDenied
	}
	if errors.Is(err, ErrState) {
		return ErrState
	}
	return ErrDependency
}

// Delegate creates a job from trusted user context after authorization. The
// dispatcher, not the client, chooses worker, exact operation, approval reference,
// correlation and validity. This is not an impersonation or token-issuance API.
func (p *PEP) Delegate(ctx context.Context, request Request, worker ActorPrincipal, expires time.Time) (string, error) {
	e, err := identityExecution(ctx, request.Operation, request.CorrelationID)
	if err != nil {
		return "", err
	}
	if p.Delegations == nil || !nonempty(string(worker)) || !nonempty(request.ApprovalID) {
		return "", ErrDenied
	}
	if err := p.authorize(ctx, e); err != nil {
		return "", err
	}
	e.Actor = worker
	if err := p.authorize(ctx, e); err != nil {
		return "", err
	}
	now := p.now()
	if !expires.After(now) {
		return "", ErrDenied
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrDependency
	}
	d := Delegation{ID: hex.EncodeToString(id[:]), Execution: e, ApprovalID: request.ApprovalID,
		IssuedAt: now, ExpiresAt: expires}
	if err := p.Delegations.Create(ctx, d); err != nil {
		return "", ErrDependency
	}
	return d.ID, nil
}

func (p *PEP) result(e Execution, err error) error {
	if p.Audit == nil {
		return ErrDependency
	}
	outcome := "denied"
	if err == nil {
		outcome = "allowed"
	}
	// Minimal metadata only: never errors, request bodies, claims, credentials or
	// full approval/delegation objects. The logger sanitizes before serialization.
	if auditErr := p.Audit.Emit(map[string]any{
		"event": "protected_execution", "outcome": outcome,
		"tenant_id": string(e.TenantID), "actor_id": string(e.Actor),
		"subject_id": string(e.Subject), "action": e.Operation.Action,
		"resource_id": e.Operation.ResourceID, "correlation_id": e.CorrelationID,
	}); auditErr != nil {
		return ErrDependency
	}
	return err
}
