// Package ratelimit supplies a provider-neutral cost admission boundary.
// It selects no price units, limits, windows, refunds or production backend.
package ratelimit

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantidentity"
)

var (
	ErrDenied      = errors.New("cost admission denied")
	ErrUnavailable = errors.New("cost admission unavailable")
	ErrInvalid     = errors.New("invalid cost admission")
	ErrReplay      = errors.New("cost admission already used")
)

// Key is a structured tenant partition. Never concatenate unescaped fields in
// an adapter. Policy chooses bucket/epoch semantics; the core supplies tenant.
type Key struct {
	Tenant        tenantidentity.TenantID
	Bucket, Epoch string
}

func (k Key) Encode() string {
	var b strings.Builder
	for _, s := range []string{string(k.Tenant), k.Bucket, k.Epoch} {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	return b.String()
}

// Quote is produced ONLY by an approved server policy. Attempt identifies an
// admission attempt, not a queue delivery or client idempotency key. Policy must
// define intentional retry accounting; the core never invents refunds/new IDs.
type Quote struct {
	Bucket, Epoch, Version, Attempt string
	Cost, Limit                     int64
}
type Policy interface {
	Quote(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error)
}
type Debit struct {
	Key              Key
	Version, Attempt string
	Cost, Limit      int64
	Execution        authorization.Execution
	Stage            authorization.AdmissionStage
}
type Outcome uint8

const (
	Rejected Outcome = iota
	Admitted
	Duplicate
)

type Receipt struct {
	Debit   Debit
	Outcome Outcome
}

// Accounting is a trusted adapter contract: atomic check-and-debit across ALL
// processes; durable, tenant-scoped attempt uniqueness; exact binding of cost,
// budget, operation, actor/subject and stage; changed reuse rejected. A duplicate
// never grants another execution. Uncertain writes must not be refunded/reissued
// silently. No TTL/reset, persistence, replay or settlement schema is selected.
type Accounting interface {
	TryDebit(context.Context, Debit) (Receipt, error)
}
type Core struct {
	policy  Policy
	backend Accounting
	audit   *audit.Recorder
}

func New(p Policy, b Accounting, a *audit.Recorder) (*Core, error) {
	if p == nil || b == nil || a == nil {
		return nil, ErrUnavailable
	}
	return &Core{p, b, a}, nil
}

// CanDebit avoids signed overflow even at MaxInt64. Only positive cost-bearing
// admissions use this primitive; exemption/zero-cost classification is policy work.
func CanDebit(used, cost, limit int64) bool {
	return used >= 0 && cost > 0 && limit > 0 && used <= limit && cost <= limit-used
}
func valid(e authorization.Execution) bool {
	t, err := tenantidentity.ParseTenantID(string(e.TenantID))
	return err == nil && t == e.TenantID && strings.TrimSpace(string(e.Actor)) != "" && strings.TrimSpace(string(e.Subject)) != "" &&
		strings.TrimSpace(e.Operation.Action) != "" && strings.TrimSpace(e.Operation.ResourceID) != "" &&
		strings.TrimSpace(e.Operation.InputFingerprint) != "" && strings.TrimSpace(e.CorrelationID) != ""
}

type admissionKey struct{}

// Admit implements authorization.Admission. Execution is supplied by the bound
// PEP after trusted identity/delegation resolution, never decoded from a request.
// Positive admission is not a reusable token and cannot bypass the final PEP.
func (c *Core) Admit(ctx context.Context, e authorization.Execution, stage authorization.AdmissionStage) error {
	if c == nil || c.policy == nil || c.backend == nil || c.audit == nil {
		return ErrUnavailable
	}
	if audit.InEmission(ctx) || ctx.Value(admissionKey{}) != nil {
		return ErrDenied
	}
	ctx = context.WithValue(ctx, admissionKey{}, true)
	if ctx.Err() != nil || !valid(e) || (stage != authorization.PreparationStage && stage != authorization.ExecutionStage) {
		return ErrInvalid
	}
	identity, ok := tenantidentity.FromContext(ctx)
	if !ok || identity.TenantID != e.TenantID || identity.PrincipalID != string(e.Subject) {
		return ErrDenied
	}
	if !authorization.MatchesExecutionIdentity(ctx, e) {
		return ErrDenied
	}
	q, err := c.policy.Quote(ctx, e, stage)
	if err != nil {
		return ErrUnavailable
	}
	if strings.TrimSpace(q.Bucket) == "" || strings.TrimSpace(q.Epoch) == "" || strings.TrimSpace(q.Version) == "" || strings.TrimSpace(q.Attempt) == "" || !CanDebit(0, q.Cost, q.Limit) {
		return ErrInvalid
	}
	d := Debit{Key: Key{e.TenantID, q.Bucket, q.Epoch}, Version: q.Version, Attempt: q.Attempt, Cost: q.Cost, Limit: q.Limit, Execution: e, Stage: stage}
	emit := func(kind string, result audit.Result) error {
		return c.audit.Record(ctx, audit.Input{Kind: kind, Result: result, Attribution: audit.Attribution{
			Tenant: string(e.TenantID), Actor: string(e.Actor), Subject: string(e.Subject), Action: e.Operation.Action, Resource: e.Operation.ResourceID, Correlation: e.CorrelationID}})
	}
	// Pending never promises debit, authorization, or execution success.
	if emit("cost_admission", audit.Pending) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	r, err := c.backend.TryDebit(ctx, d)
	if err != nil || ctx.Err() != nil || r.Debit != d {
		_ = emit("cost_admission", audit.Failed)
		return ErrUnavailable
	}
	switch r.Outcome {
	case Admitted:
		// This is the observed durable DEBIT, never authentication/operation
		// success. A sink failure cannot undo it; no automatic refund is made.
		if emit("cost_debit", audit.Committed) != nil || ctx.Err() != nil {
			return ErrUnavailable
		}
		return nil
	case Duplicate:
		if emit("cost_admission", audit.Denied) != nil {
			return ErrUnavailable
		}
		return ErrReplay
	case Rejected:
		if emit("cost_admission", audit.Denied) != nil {
			return ErrUnavailable
		}
		return ErrDenied
	default:
		return ErrUnavailable
	}
}
