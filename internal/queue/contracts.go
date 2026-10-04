// Package queue implements the CYB-15 metadata-only processing foundation.
// Production topology, codecs, retry values, state persistence and replay remain
// injected decisions. Queue references are locators, never authority or grants.
package queue

import (
	"context"
	"time"

	"cyber-ai-platform/internal/audit"
)

// Metadata is an in-memory contract, not a selected production wire schema.
// Reference locates immutable CYB-13 delegation state; no tenant/actor/subject,
// payload, approval, credential or retry budget is accepted from the message.
type Metadata struct {
	Schema    string
	Version   string
	Reference string
}

type Fields map[string]string

type Delivery struct {
	ID     string
	Fields Fields
	// Invalid preserves a source ID for a malformed/missing Redis body. Never
	// retain or copy the original unparseable body into diagnostics or the DLQ.
	Invalid bool
}

type DeliveryKey struct{ Stream, Group, ID string }
type Pending struct {
	ID         string
	Consumer   string
	Idle       time.Duration
	Deliveries uint64 // transport observations, NEVER the processing retry budget
}

// DeadLetter is a safe projection. It references the source entry, not its raw
// contents or untrusted reference. Access/retention/replay policies remain TBD.
type DeadLetter struct {
	SourceID string
	Class    Class
	Reason   Reason
	Attempts uint32
}

// Broker is configured only by trusted server code. Key validates transport IDs
// and supplies the server-selected stream/group; no routing comes from payloads.
// Publish and WriteDLQ return confirmed entry IDs or safe errors. A timeout can
// have an uncertain write outcome; this interface makes no exactly-once claim.
type Broker interface {
	Key(string) (DeliveryKey, error)
	Publish(context.Context, Fields) (string, error)
	Read(context.Context, int64) ([]Delivery, error)
	Pending(context.Context, int64) ([]Pending, error)
	Claim(context.Context, []string, time.Duration) ([]Delivery, error)
	Ack(context.Context, string) error
	WriteDLQ(context.Context, DeadLetter) (string, error)
}

// Processor is a trusted server adapter, never a request callback. Authorize
// must independently verify worker/delegation and fresh actor AND subject PDP,
// including ACK-only recovery. Process must use the existing PEP execution and
// CYB-14 payload boundary. ProtectedProcessor supplies that implementation.
type Processor interface {
	// VerifyWorker rejects unverified callers before queue/control operations.
	// Per-job denial is separate: it must still produce sanitized DLQ data.
	VerifyWorker(context.Context) error
	Authorize(context.Context, Metadata) error
	Process(context.Context, Metadata) error
}

type Phase uint8

const (
	Ready Phase = iota
	Completed
	DLQPending
	DLQWritten
)

// State contains transport progress only, not business idempotency semantics.
// A record is permanently bound to the validated message observed for that
// delivery. Completion is not atomic with PostgreSQL business commit.
type State struct {
	Bound     bool
	Message   Metadata
	Attempts  uint32
	NotBefore time.Time
	Phase     Phase
	Failure   Classification
}

// Store implementations provide exclusive, fenced per-delivery leases and
// durable, monotonic progress across consumers/restarts. Save must persist an
// attempt BEFORE Process. No production schema/backend/default is supplied.
// In-memory test doubles are not suitable for production retry accounting.
type Store interface {
	Acquire(context.Context, DeliveryKey) (Lease, error)
}
type Lease interface {
	Load(context.Context) (State, error)
	Save(context.Context, State) error
	Release(context.Context) error
}

// RetryPolicy has no default values. MaxAttempts bounds processing-attempt slots
// per delivery (including the first, preflight/audit failures, and failed fresh
// authorization during completed recovery); it must be explicitly nonzero.
// Backoff is trusted configuration and must return a nonnegative duration.
// This defines interface counting, not a production retry/backoff decision.
type RetryPolicy struct {
	MaxAttempts uint32
	Backoff     func(attempt uint32) time.Duration
}

type ConsumerConfig struct {
	Broker    Broker
	Schema    *Schema
	Processor Processor
	Store     Store
	Retry     RetryPolicy
	Audit     *audit.Logger
	Now       func() time.Time // nil uses server time; never a queue timestamp
}
