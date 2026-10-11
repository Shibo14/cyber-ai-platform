package authorization

import (
	"context"
	"cyber-ai-platform/internal/tenantdb"
	"cyber-ai-platform/internal/tenantidentity"
)

// MatchesExecutionIdentity checks trusted in-process principal attribution only;
// it is not an authorization decision or a substitute for VerifyWorker/PDP.
func MatchesExecutionIdentity(ctx context.Context, e Execution) bool {
	a, ok := ctx.Value(actorKey{}).(verifiedActor)
	i, exists := tenantidentity.FromContext(ctx)
	return ok && exists && validExecution(e) && a.id == e.Actor && i.TenantID == e.TenantID && i.PrincipalID == string(e.Subject)
}

// AdmissionStage identifies a cost-bearing boundary, not a pricing unit.
type AdmissionStage string

const (
	PreparationStage AdmissionStage = "preparation"
	ExecutionStage   AdmissionStage = "execution"
)

// Admission is trusted server wiring. Its positive result is budget admission
// only, never authorization. Remote debits cannot roll back with the DB.
type Admission interface {
	Admit(context.Context, Execution, AdmissionStage) error
}

// BindAdmission explicitly opts a protected flow into mandatory cost admission.
// Use the returned PEP in CYB-14/15 constructors. Existing unbound foundations
// remain unchanged; production coverage/wiring and cost classification are TBD.
func BindAdmission(p *PEP, gate Admission) (*PEP, error) {
	if p == nil || gate == nil {
		return nil, ErrDependency
	}
	bound := *p
	bound.admission = gate
	return &bound, nil
}
func (p *PEP) admit(ctx context.Context, e Execution, stage AdmissionStage) error {
	if p.admission == nil {
		return nil
	}
	if p.admission.Admit(ctx, e, stage) != nil {
		return ErrDependency
	}
	// Admission/audit can block. Recheck worker evidence AND actor/subject PDP.
	if ctx.Err() != nil {
		return ErrDependency
	}
	if err := p.authorize(ctx, e); err != nil {
		return err
	}
	// PDP itself may block after its initial worker guard.
	if a, ok := ctx.Value(actorKey{}).(verifiedActor); ok && a.worker {
		return p.VerifyWorker(ctx)
	}
	return nil
}

// executionPreflight is a short, non-consuming transaction. Its observations
// are advisory: the final execution transaction reloads approval/state/delegation
// and reauthorizes after admission. No DB transaction spans remote admission.
func (p *PEP) executionPreflight(ctx context.Context, e Execution, approvalID string, d *Delegation, tool Tool) error {
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
		state, err := tool.LockState(ctx, tx, e)
		if err != nil {
			return ErrDependency
		}
		if !validApproval(a, approvalID, e, state, p.now()) ||
			(d != nil && !validDelegation(*d, d.ID, e, p.now())) {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return preparationError(err)
	}
	return nil
}
