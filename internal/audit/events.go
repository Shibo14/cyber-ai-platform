package audit

import (
	"context"
	"errors"
	"strings"
	"time"

	"cyber-ai-platform/internal/tenantidentity"
)

var (
	ErrInvalidEvent = errors.New("invalid audit event")
	ErrAccess       = errors.New("audit access denied")
	ErrUnavailable  = errors.New("audit dependency unavailable")
	ErrIntegrity    = errors.New("audit integrity verification failed")
	// A writer may persist before reporting an error. This never means rollback.
	ErrDeliveryUnknown = errors.New("audit delivery unconfirmed")
	ErrRecursion       = errors.New("recursive security emission denied")
)

// Result describes an observed stage, never a promise about a later stage.
// Pending cannot be interpreted as authentication or business success.
type Result string

const (
	Pending   Result = "pending"
	Denied    Result = "denied"
	Failed    Result = "failed"
	Succeeded Result = "succeeded"
	Committed Result = "committed"
)

// Attribution is supplied by trusted application wiring, not request fields.
// Tenant is empty only for genuinely unscoped events (e.g. failed handshake).
type Attribution struct{ Tenant, Actor, Subject, Action, Resource, Correlation string }
type Input struct {
	Attribution
	Kind   string
	Result Result
}
type Data struct {
	Input
	Timestamp time.Time
}

// Privacy must project EVERY nonempty reference to an approved non-sensitive
// reference or reject it. No arbitrary free-text pass-through default exists.
// This is a trusted adapter for approved PII rules, not a generic PII detector.
type Privacy interface {
	Reference(context.Context, string, string) (string, error)
}

// Taxonomy approves exact combinations and required fields; no final schema is selected.
type Taxonomy interface {
	Validate(context.Context, Input) error
}
type Builder struct {
	privacy  Privacy
	taxonomy Taxonomy
	now      func() time.Time
}
type Event struct {
	data  Data
	valid bool
}

func (e Event) Data() Data { return e.data } // value copy; no mutable metadata bags

func NewBuilder(p Privacy, t Taxonomy, now func() time.Time) (*Builder, error) {
	if p == nil || t == nil || now == nil {
		return nil, ErrInvalidEvent
	}
	return &Builder{p, t, now}, nil
}
func (b *Builder) Build(ctx context.Context, in Input) (Event, error) {
	if b == nil || b.privacy == nil || b.taxonomy == nil || b.now == nil || ctx.Err() != nil || strings.TrimSpace(in.Kind) == "" {
		return Event{}, ErrInvalidEvent
	}
	switch in.Result {
	case Pending, Denied, Failed, Succeeded, Committed:
	default:
		return Event{}, ErrInvalidEvent
	}
	if in.Tenant != "" {
		t, err := tenantidentity.ParseTenantID(in.Tenant)
		if err != nil || string(t) != in.Tenant {
			return Event{}, ErrInvalidEvent
		}
	}
	if b.taxonomy.Validate(ctx, in) != nil {
		return Event{}, ErrInvalidEvent
	}
	// Kind is a server-approved taxonomy value; attribution is projected before
	// serialization. Tenant remains canonical for access checks and partitioning.
	for _, f := range []struct {
		name  string
		value *string
	}{
		{"actor", &in.Actor}, {"subject", &in.Subject}, {"action", &in.Action},
		{"resource", &in.Resource}, {"correlation", &in.Correlation},
	} {
		if *f.value == "" {
			continue
		}
		v, err := b.privacy.Reference(ctx, f.name, *f.value)
		if err != nil || strings.TrimSpace(v) == "" || Sanitize(v) == Redacted {
			return Event{}, ErrInvalidEvent
		}
		*f.value = v
	}
	if Sanitize(in.Kind) == Redacted || ctx.Err() != nil {
		return Event{}, ErrInvalidEvent
	}
	now := b.now()
	if now.IsZero() {
		return Event{}, ErrInvalidEvent
	}
	return Event{Data{Input: in, Timestamp: now.UTC()}, true}, nil
}

type emissionKey struct{}

// InEmission lets cost admission reject audit -> limiter -> audit recursion.
// Adapters must propagate the supplied context; discarding it violates the contract.
func InEmission(ctx context.Context) bool { v, _ := ctx.Value(emissionKey{}).(bool); return v }

// Writer must preserve observed event semantics on partial/uncertain writes.
// Durability, serialization, storage, retention and integrity mechanism are unselected.
type Writer interface {
	Write(context.Context, Event) error
}
type Recorder struct {
	builder *Builder
	writer  Writer
}

func NewRecorder(b *Builder, w Writer) (*Recorder, error) {
	if b == nil || w == nil {
		return nil, ErrUnavailable
	}
	return &Recorder{b, w}, nil
}
func (r *Recorder) Record(ctx context.Context, in Input) error {
	if r == nil || r.builder == nil || r.writer == nil {
		return ErrUnavailable
	}
	if InEmission(ctx) {
		return ErrRecursion
	}
	ctx = context.WithValue(ctx, emissionKey{}, true)
	e, err := r.builder.Build(ctx, in)
	if err != nil {
		return err
	}
	if r.writer.Write(ctx, e) != nil || ctx.Err() != nil {
		return ErrDeliveryUnknown
	}
	return nil
}
