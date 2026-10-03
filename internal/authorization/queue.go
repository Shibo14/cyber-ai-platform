package authorization

import (
	"context"

	"cyber-ai-platform/internal/tenantidentity"
)

// VerifyWorker checks the existing trusted workload-verification marker only.
// It introduces no identity protocol and accepts no Redis/client identity.
// Queue transports use it before even poison-message or ACK-only handling;
// per-job authority still requires ResolveWorker and protected execution.
func (p *PEP) VerifyWorker(ctx context.Context) error {
	if p == nil {
		return ErrDependency
	}
	actor, ok := ctx.Value(actorKey{}).(verifiedActor)
	if !ok || !actor.worker || !nonempty(string(actor.id)) {
		return ErrDenied
	}
	return nil
}

// ResolveWorker resolves an opaque delegation reference for queue processing.
// It is a non-consuming authorization preflight, never an authority grant or a
// replacement for ExecuteWorker/ExecuteWorkerPrepared. Those entry points load
// the delegation and recheck PDP, approval and resource state at execution.
// Redis consumer names, claims and message fields cannot establish identity.
func (p *PEP) ResolveWorker(ctx context.Context, delegationID string) (WorkerRequest, error) {
	if err := p.VerifyWorker(ctx); err != nil {
		return WorkerRequest{}, err
	}
	if !nonempty(delegationID) {
		return WorkerRequest{}, ErrDenied
	}
	if p == nil || p.Delegations == nil || p.Audit == nil {
		return WorkerRequest{}, ErrDependency
	}
	// The initial lookup supplies only the exact operation/correlation. Reusing
	// workerExecution performs all immutable binding, identity and expiry checks
	// on a fresh authoritative load rather than trusting a queue representation.
	d, err := p.Delegations.Load(ctx, delegationID)
	if err != nil {
		return WorkerRequest{}, ErrDependency
	}
	request := WorkerRequest{DelegationID: delegationID, Operation: d.Execution.Operation,
		CorrelationID: d.Execution.CorrelationID}
	d, err = p.workerExecution(ctx, request)
	if err != nil {
		return WorkerRequest{}, err
	}
	trusted := tenantidentity.WithAuthenticatedIdentity(ctx, tenantidentity.Identity{
		TenantID: d.Execution.TenantID, PrincipalID: string(d.Execution.Subject),
	})
	if err := p.authorize(trusted, d.Execution); err != nil {
		return WorkerRequest{}, err
	}
	// A slow PDP must not turn an expired delegation into an ACK-only grant.
	if !validDelegation(d, delegationID, d.Execution, p.now()) {
		return WorkerRequest{}, ErrDenied
	}
	return request, nil
}
