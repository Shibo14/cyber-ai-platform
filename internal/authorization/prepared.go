package authorization

import (
	"context"
	"errors"

	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

// Preparation is a trusted adapter, not a request-supplied callback. LockState
// uses the supplied tenant transaction and binds all execution inputs. Prepare
// runs outside that transaction after authorization and approval validation.
// It must only prepare data in memory: no application persistence, plaintext
// release, queue publication or irreversible resource action. The returned Tool
// must enforce the original operation's state precondition in the final tx.
// Remote dependency calls cannot be rolled back with the database.
type Preparation interface {
	LockState(context.Context, tenantdb.TenantTx, Execution) (string, error)
	Prepare(context.Context, Execution) (Tool, error)
}

// ExecutePrepared preserves one-shot approval consumption at final execution.
// Preparation is not an authorization grant for a later, separate request.
func (p *PEP) ExecutePrepared(ctx context.Context, request Request, preparation Preparation) error {
	e, err := identityExecution(ctx, request.Operation, request.CorrelationID)
	if err == nil {
		err = p.prepared(ctx, e, request.ApprovalID, nil, preparation)
	}
	return p.result(e, err)
}

// ExecuteWorkerPrepared reconstructs authority using the existing immutable
// delegation contract. Queue authority claims never populate the trusted ctx.
func (p *PEP) ExecuteWorkerPrepared(ctx context.Context, request WorkerRequest, preparation Preparation) error {
	d, err := p.workerExecution(ctx, request)
	if err != nil {
		return p.result(Execution{}, err)
	}
	trusted := tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{
		TenantID: d.Execution.TenantID, PrincipalID: string(d.Execution.Subject),
	})
	err = p.prepared(trusted, d.Execution, d.ApprovalID, &d, preparation)
	return p.result(d.Execution, err)
}

func (p *PEP) prepared(ctx context.Context, e Execution, approvalID string, d *Delegation, preparation Preparation) error {
	if p.DB == nil || p.Approvals == nil || p.Audit == nil || preparation == nil {
		return ErrDependency
	}
	var approval Approval
	err := p.DB.WithTenantTx(ctx, func(tx tenantdb.TenantTx) error {
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
		state, err := preparation.LockState(ctx, tx, e)
		if err != nil {
			return err
		}
		if !validApproval(a, approvalID, e, state, p.now()) ||
			(d != nil && !validDelegation(*d, d.ID, e, p.now())) {
			return ErrDenied
		}
		approval = a
		return nil
	})
	if err != nil {
		return preparationError(err)
	}
	if ctx.Err() != nil {
		return ErrDependency
	}
	if !validPeriod(approval.IssuedAt, approval.ExpiresAt, p.now()) ||
		(d != nil && !validDelegation(*d, d.ID, e, p.now())) {
		return ErrDenied
	}
	tool, err := preparation.Prepare(ctx, e)
	if err != nil {
		return preparationError(err)
	}
	// Re-evaluate PDP, approval/delegation validity, immutable bindings and state;
	// only this existing final boundary atomically consumes the approval.
	return p.execute(ctx, e, approvalID, d, tool)
}

func preparationError(err error) error {
	if errors.Is(err, ErrDenied) {
		return ErrDenied
	}
	if errors.Is(err, ErrState) {
		return ErrState
	}
	return ErrDependency
}
