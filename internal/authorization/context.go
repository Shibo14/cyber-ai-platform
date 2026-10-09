// Package authorization implements the CYB-13 protected execution boundary.
// Identity providers, permission models, approval workflows and queue/storage
// implementations remain outside this package.
package authorization

import (
	"context"
	"errors"
	"strings"
	"time"

	"cyber-ai-platform/internal/tenantidentity"
)

type ActorPrincipal string
type SubjectPrincipal string

type actorKey struct{}
type verifiedActor struct {
	id     ActorPrincipal
	worker bool
	check  func(context.Context) error
}

// WithVerifiedActor is for trusted workload verification (SPIFFE/mTLS) or
// server configuration only. Never pass a client-selected workload identity.
func WithVerifiedActor(ctx context.Context, actor ActorPrincipal) context.Context {
	return context.WithValue(ctx, actorKey{}, verifiedActor{id: actor})
}

// WithVerifiedWorker marks a verified worker entry point. It cannot use the
// direct human-request path to downgrade an operation without delegation.
// This trusted in-process seam does not authenticate a certificate. Transport
// adapters should use WithVerifiedWorkerCheck for current validity checks.
func WithVerifiedWorker(ctx context.Context, actor ActorPrincipal) context.Context {
	return context.WithValue(ctx, actorKey{}, verifiedActor{id: actor, worker: true})
}

// WithVerifiedWorkerCheck is trusted transport wiring only. The check must
// revalidate the authenticated workload, never queue/client identity claims.
// A nil check is denied, rather than downgrading to the legacy trusted marker.
func WithVerifiedWorkerCheck(ctx context.Context, actor ActorPrincipal, check func(context.Context) error) context.Context {
	if check == nil {
		check = func(context.Context) error { return ErrDenied }
	}
	return context.WithValue(ctx, actorKey{}, verifiedActor{id: actor, worker: true, check: check})
}

// Operation is an exact tool operation, not a wildcard scope. The trusted tool
// adapter must compute InputFingerprint deterministically over ALL arguments
// that affect execution, and execute those same arguments. ResourceID must
// identify the object and its kind. Empty argument sets still need a fingerprint.
type Operation struct {
	Action           string
	ResourceID       string
	InputFingerprint string
}

type Execution struct {
	TenantID      tenantidentity.TenantID
	Actor         ActorPrincipal
	Subject       SubjectPrincipal
	Operation     Operation
	CorrelationID string
}

// Approval is trusted application state, never an approval supplied in a
// request payload. Only one-shot semantics are supported by this boundary.
// Stores must use unique, immutable IDs and retain consumption across retries.
type Approval struct {
	ID            string
	TenantID      tenantidentity.TenantID
	Subject       SubjectPrincipal
	Operation     Operation
	ResourceState string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Consumed      bool
}

// Delegation binds one authorized job to a particular worker and user. It is
// stored immutably on the trusted side; a queue message references its ID only.
type Delegation struct {
	ID         string
	Execution  Execution
	ApprovalID string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

var (
	ErrDenied     = errors.New("protected execution denied")
	ErrDependency = errors.New("security dependency failed")
	ErrState      = errors.New("resource state precondition failed")
)

func nonempty(value string) bool { return strings.TrimSpace(value) != "" }

func validExecution(e Execution) bool {
	tenant, err := tenantidentity.ParseTenantID(string(e.TenantID))
	return err == nil && tenant == e.TenantID && nonempty(string(e.Actor)) &&
		nonempty(string(e.Subject)) && nonempty(e.Operation.Action) &&
		nonempty(e.Operation.ResourceID) && nonempty(e.Operation.InputFingerprint) &&
		nonempty(e.CorrelationID)
}

func validPeriod(issued, expires, now time.Time) bool {
	return !issued.IsZero() && expires.After(issued) && !now.Before(issued) && now.Before(expires)
}

func identityExecution(ctx context.Context, op Operation, correlation string) (Execution, error) {
	identity, ok := tenantidentity.FromContext(ctx)
	actor, actorOK := ctx.Value(actorKey{}).(verifiedActor)
	e := Execution{TenantID: identity.TenantID, Subject: SubjectPrincipal(identity.PrincipalID),
		Actor: actor.id, Operation: op, CorrelationID: correlation}
	if !ok || !actorOK || actor.worker || !validExecution(e) {
		return Execution{}, ErrDenied
	}
	return e, nil
}

func validApproval(a Approval, id string, e Execution, state string, now time.Time) bool {
	return nonempty(id) && a.ID == id && !a.Consumed && a.TenantID == e.TenantID &&
		a.Subject == e.Subject && a.Operation == e.Operation && nonempty(state) &&
		a.ResourceState == state && validPeriod(a.IssuedAt, a.ExpiresAt, now)
}

func validDelegation(d Delegation, id string, e Execution, now time.Time) bool {
	return nonempty(id) && d.ID == id && d.Execution == e &&
		nonempty(d.ApprovalID) && validExecution(d.Execution) &&
		validPeriod(d.IssuedAt, d.ExpiresAt, now)
}
