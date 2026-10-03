package queue

import (
	"context"
	"time"
)

type Outcome string

const (
	Acknowledged Outcome = "acknowledged"
	DeadLettered Outcome = "dead_lettered"
	Deferred     Outcome = "deferred"
	Unconfirmed  Outcome = "unconfirmed"
)

type Result struct {
	Outcome  Outcome
	Failure  Classification
	Attempts uint32
}

type Consumer struct{ config ConsumerConfig }

func NewConsumer(config ConsumerConfig) (*Consumer, error) {
	if config.Broker == nil || config.Schema == nil || config.Processor == nil || config.Store == nil ||
		config.Audit == nil || config.Retry.MaxAttempts == 0 || config.Retry.Backoff == nil {
		return nil, ErrConfiguration
	}
	return &Consumer{config}, nil
}

func (c *Consumer) now() time.Time {
	if c.config.Now != nil {
		return c.config.Now()
	}
	return time.Now()
}

// Handle performs at most one processing attempt. It never sleeps or runs an
// unbounded retry loop. Dependencies/ACK/DLQ failures leave the source pending.
// Store progress is not atomic with the PEP transaction: a crash in that gap
// requires approved business reconciliation; one-shot approval is never reset.
func (c *Consumer) Handle(ctx context.Context, delivery Delivery) (result Result, retErr error) {
	result.Outcome = Unconfirmed
	if err := c.config.Processor.VerifyWorker(ctx); err != nil {
		return result, Classify(err)
	}
	key, err := c.config.Broker.Key(delivery.ID)
	if err != nil || key.ID != delivery.ID || key.Stream == "" || key.Group == "" {
		return result, ErrProtocol
	}
	lease, err := c.config.Store.Acquire(ctx, key)
	if err != nil {
		return result, ErrStore
	}
	if lease == nil {
		return result, ErrStore
	}
	defer func() {
		if err := lease.Release(context.WithoutCancel(ctx)); err != nil {
			retErr = ErrStore
		}
	}()
	state, err := lease.Load(ctx)
	if err != nil || !c.validState(state) {
		return result, ErrStore
	}
	result.Attempts = state.Attempts
	m, decodeErr := c.config.Schema.Decode(delivery.Fields)
	if delivery.Invalid {
		decodeErr = ErrMalformed
	}
	if decodeErr != nil {
		return c.deadLetter(ctx, lease, key, state, Classify(decodeErr))
	}
	if state.Bound && state.Message != m {
		return c.deadLetter(ctx, lease, key, state, Classification{Permanent, Denied})
	}
	if !state.Bound {
		state.Bound, state.Message = true, m
		if err := lease.Save(ctx, state); err != nil {
			return result, ErrStore
		}
	}
	// Terminal recovery never repeats business execution. Still revalidate the
	// verified worker and fresh PDP before trusting a completed transport record.
	if state.Phase == Completed {
		if c.now().Before(state.NotBefore) {
			return Result{Outcome: Deferred, Failure: state.Failure, Attempts: state.Attempts}, ErrDeferred
		}
		if err := c.config.Processor.Authorize(ctx, m); err != nil {
			failure := Classify(err)
			if failure.Class == Permanent || state.Attempts >= c.config.Retry.MaxAttempts {
				return c.deadLetter(ctx, lease, key, state, failure)
			}
			state.Attempts++
			if state.Attempts >= c.config.Retry.MaxAttempts {
				return c.deadLetter(ctx, lease, key, state, failure)
			}
			delay := c.config.Retry.Backoff(state.Attempts)
			if delay < 0 {
				return result, ErrConfiguration
			}
			state.Failure, state.NotBefore = failure, c.now().Add(delay)
			if err := lease.Save(ctx, state); err != nil {
				return result, ErrStore
			}
			if err := c.emit("recovery_retry", failure, state.Attempts); err != nil {
				return result, err
			}
			return Result{Outcome: Deferred, Failure: failure, Attempts: state.Attempts}, ErrDeferred
		}
		if err := c.emit("completion_recovery", Classification{}, state.Attempts); err != nil {
			return result, err
		}
		if err := c.config.Broker.Ack(ctx, key.ID); err != nil {
			return result, ErrACK
		}
		return Result{Outcome: Acknowledged, Attempts: state.Attempts}, nil
	}
	if state.Phase == DLQPending || state.Phase == DLQWritten {
		// A denial is itself a permanent DLQ outcome, not a grant to access any
		// payload. No protected processing occurs on this recovery path.
		if state.Bound {
			if err := c.config.Processor.Authorize(ctx, m); err != nil {
				failure := Classify(err)
				// Permanent operation denial is already a terminal failure, not
				// payload access. Dependency failure prevents ACK-only recovery.
				if failure.Class != Permanent {
					return result, failure
				}
			}
		}
		return c.deadLetter(ctx, lease, key, state, state.Failure)
	}
	if c.now().Before(state.NotBefore) {
		return Result{Outcome: Deferred, Failure: state.Failure, Attempts: state.Attempts}, ErrDeferred
	}
	if state.Attempts >= c.config.Retry.MaxAttempts {
		failure := state.Failure
		if !failure.Valid() {
			failure = Classification{Unknown, Unclassified}
		}
		return c.deadLetter(ctx, lease, key, state, failure)
	}
	state.Attempts++
	state.NotBefore = time.Time{}
	if err := lease.Save(ctx, state); err != nil {
		return result, ErrStore
	}
	result.Attempts = state.Attempts
	if err := c.emit("attempt", Classification{}, state.Attempts); err != nil {
		return result, err
	}
	processErr := c.config.Processor.Authorize(ctx, m)
	if processErr == nil {
		processErr = c.config.Processor.Process(ctx, m)
	}
	if processErr != nil {
		failure := Classify(processErr)
		if failure.Class == Permanent || state.Attempts >= c.config.Retry.MaxAttempts {
			return c.deadLetter(ctx, lease, key, state, failure)
		}
		delay := c.config.Retry.Backoff(state.Attempts)
		if delay < 0 {
			return result, ErrConfiguration
		}
		state.Failure, state.NotBefore = failure, c.now().Add(delay)
		if err := lease.Save(ctx, state); err != nil {
			return result, ErrStore
		}
		if err := c.emit("retry", failure, state.Attempts); err != nil {
			return result, err
		}
		return Result{Outcome: Deferred, Failure: failure, Attempts: state.Attempts}, ErrDeferred
	}
	state.Phase, state.Failure = Completed, Classification{}
	if err := lease.Save(ctx, state); err != nil {
		return result, ErrStore
	}
	if err := c.emit("completed", Classification{}, state.Attempts); err != nil {
		return result, err
	}
	if err := c.config.Broker.Ack(ctx, key.ID); err != nil {
		return result, ErrACK
	}
	return Result{Outcome: Acknowledged, Attempts: state.Attempts}, nil
}

func (c *Consumer) validState(s State) bool {
	if s.Phase > DLQWritten || s.Attempts > c.config.Retry.MaxAttempts {
		return false
	}
	if s.Bound {
		if c.config.Schema.Validate(s.Message) != nil {
			return false
		}
	} else if s.Message != (Metadata{}) || s.Attempts != 0 || s.Phase == Completed {
		return false
	}
	if s.Phase == Completed && s.Attempts == 0 {
		return false
	}
	if s.Phase == DLQPending || s.Phase == DLQWritten {
		return s.Failure.Valid()
	}
	return s.Failure == (Classification{}) || s.Failure.Valid()
}

func (c *Consumer) deadLetter(ctx context.Context, lease Lease, key DeliveryKey, state State, failure Classification) (Result, error) {
	result := Result{Outcome: Unconfirmed, Failure: failure, Attempts: state.Attempts}
	if !failure.Valid() {
		return result, ErrStore
	}
	if state.Phase != DLQWritten {
		state.Phase, state.Failure, state.NotBefore = DLQPending, failure, time.Time{}
		if err := lease.Save(ctx, state); err != nil {
			return result, ErrStore
		}
		id, err := c.config.Broker.WriteDLQ(ctx, DeadLetter{SourceID: key.ID, Class: failure.Class, Reason: failure.Reason, Attempts: state.Attempts})
		if err != nil || id == "" {
			return result, ErrDLQ
		}
		state.Phase = DLQWritten
		if err := lease.Save(ctx, state); err != nil {
			return result, ErrStore
		}
	}
	if err := c.emit("dlq", state.Failure, state.Attempts); err != nil {
		return result, err
	}
	if err := c.config.Broker.Ack(ctx, key.ID); err != nil {
		return result, ErrACK
	}
	result.Outcome, result.Failure = DeadLettered, state.Failure
	return result, nil
}

func (c *Consumer) emit(outcome string, failure Classification, attempts uint32) error {
	if err := c.config.Audit.Emit(map[string]any{
		"event": "queue_transition", "outcome": outcome, "failure_class": string(failure.Class),
		"reason": string(failure.Reason), "attempts": attempts,
	}); err != nil {
		return ErrAudit
	}
	return nil
}

// Consume reads one bounded batch. Results preserve progress; the first safe
// control error is returned after the batch. There is no daemon/replay policy.
func (c *Consumer) Consume(ctx context.Context, count int64) ([]Result, error) {
	if err := c.config.Processor.VerifyWorker(ctx); err != nil {
		return nil, Classify(err)
	}
	if count <= 0 {
		return nil, ErrConfiguration
	}
	deliveries, err := c.config.Broker.Read(ctx, count)
	if err != nil {
		return nil, ErrDependency
	}
	return c.batch(ctx, deliveries)
}

// Recover claims only sufficiently idle pending entries. Claim changes delivery
// ownership only; Handle still performs the same PEP checks. Redis delivery
// counters cannot alter the injected server-side processing retry budget.
func (c *Consumer) Recover(ctx context.Context, count int64, minIdle time.Duration) ([]Result, error) {
	if err := c.config.Processor.VerifyWorker(ctx); err != nil {
		return nil, Classify(err)
	}
	if count <= 0 || minIdle <= 0 {
		return nil, ErrConfiguration
	}
	pending, err := c.config.Broker.Pending(ctx, count)
	if err != nil {
		return nil, ErrDependency
	}
	ids := make([]string, 0, len(pending))
	for _, p := range pending {
		if p.Idle >= minIdle {
			ids = append(ids, p.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	deliveries, err := c.config.Broker.Claim(ctx, ids, minIdle)
	if err != nil {
		return nil, ErrDependency
	}
	return c.batch(ctx, deliveries)
}

func (c *Consumer) batch(ctx context.Context, deliveries []Delivery) ([]Result, error) {
	results := make([]Result, 0, len(deliveries))
	var first error
	for _, d := range deliveries {
		r, err := c.Handle(ctx, d)
		results = append(results, r)
		if err != nil && first == nil {
			first = err
		}
	}
	return results, first
}
