package queue

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/encryption"
)

// These durable-for-the-test, mutex-serialized doubles are not production
// persistence, lease, idempotency, topology or retry policy selections.
type queueTestStore struct {
	mu         sync.Mutex
	items      map[DeliveryKey]*queueTestLease
	acquireErr error
	saveErr    func(State) error
}
type queueTestLease struct {
	mu    sync.Mutex
	state State
	store *queueTestStore
}

func (s *queueTestStore) Acquire(_ context.Context, k DeliveryKey) (Lease, error) {
	s.mu.Lock()
	if s.acquireErr != nil {
		s.mu.Unlock()
		return nil, s.acquireErr
	}
	if s.items == nil {
		s.items = make(map[DeliveryKey]*queueTestLease)
	}
	l := s.items[k]
	if l == nil {
		l = &queueTestLease{store: s}
		s.items[k] = l
	}
	s.mu.Unlock()
	l.mu.Lock()
	return l, nil
}
func (l *queueTestLease) Load(context.Context) (State, error) { return l.state, nil }
func (l *queueTestLease) Save(_ context.Context, s State) error {
	if l.store.saveErr != nil {
		if err := l.store.saveErr(s); err != nil {
			return err
		}
	}
	l.state = s
	return nil
}
func (l *queueTestLease) Release(context.Context) error { l.mu.Unlock(); return nil }

type queueTestBroker struct {
	delivery                                      []Delivery
	pending                                       []Pending
	claimed                                       []Delivery
	letters                                       []DeadLetter
	acks                                          int
	ackErr, dlqErr, readErr, claimErr, pendingErr error
	commands                                      []string
}

func (*queueTestBroker) Key(id string) (DeliveryKey, error) {
	if id == "" {
		return DeliveryKey{}, ErrProtocol
	}
	return DeliveryKey{"fixture-stream", "fixture-group", id}, nil
}
func (b *queueTestBroker) Publish(_ context.Context, f Fields) (string, error) {
	b.delivery = append(b.delivery, Delivery{ID: "1-0", Fields: f})
	return "1-0", nil
}
func (b *queueTestBroker) Read(context.Context, int64) ([]Delivery, error) {
	return b.delivery, b.readErr
}
func (b *queueTestBroker) Pending(context.Context, int64) ([]Pending, error) {
	return b.pending, b.pendingErr
}
func (b *queueTestBroker) Claim(context.Context, []string, time.Duration) ([]Delivery, error) {
	b.commands = append(b.commands, "claim")
	return b.claimed, b.claimErr
}
func (b *queueTestBroker) Ack(context.Context, string) error {
	b.acks++
	b.commands = append(b.commands, "ack")
	return b.ackErr
}
func (b *queueTestBroker) WriteDLQ(_ context.Context, d DeadLetter) (string, error) {
	b.commands = append(b.commands, "dlq")
	if b.dlqErr != nil {
		return "", b.dlqErr
	}
	b.letters = append(b.letters, d)
	return "2-0", nil
}

type queueTestProcessor struct {
	authorizations, calls   int
	verifyErr, authErr, err error
}

func (p *queueTestProcessor) VerifyWorker(context.Context) error { return p.verifyErr }

func (p *queueTestProcessor) Authorize(context.Context, Metadata) error {
	p.authorizations++
	return p.authErr
}
func (p *queueTestProcessor) Process(context.Context, Metadata) error { p.calls++; return p.err }

type queueFixture struct {
	c         *Consumer
	broker    *queueTestBroker
	store     *queueTestStore
	processor *queueTestProcessor
	schema    *Schema
	delivery  Delivery
	log       bytes.Buffer
	now       time.Time
}

func testSchema(t *testing.T) *Schema {
	t.Helper()
	s, err := NewSchema(SchemaConfig{ID: "fixture", Version: "test-version", SchemaField: "schema", VersionField: "version", ReferenceField: "ref", ValidReference: func(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 16 }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func newQueueFixture(t *testing.T) *queueFixture {
	t.Helper()
	f := &queueFixture{broker: &queueTestBroker{}, store: &queueTestStore{}, processor: &queueTestProcessor{}, schema: testSchema(t), now: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	fields, err := f.schema.Encode(f.schema.Metadata("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	f.delivery = Delivery{ID: "1-0", Fields: fields}
	f.c, err = NewConsumer(ConsumerConfig{Broker: f.broker, Schema: f.schema, Processor: f.processor, Store: f.store, Retry: RetryPolicy{MaxAttempts: 3, Backoff: func(uint32) time.Duration { return time.Second }}, Audit: audit.New(&f.log, "event", "outcome", "failure_class", "reason", "attempts"), Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestConsumeCompletionACKAndDuplicate(t *testing.T) {
	f := newQueueFixture(t)
	f.broker.delivery = []Delivery{f.delivery}
	results, err := f.c.Consume(context.Background(), 1)
	if err != nil || len(results) != 1 || results[0].Outcome != Acknowledged || f.processor.calls != 1 || f.broker.acks != 1 {
		t.Fatalf("completion: %#v %v", results, err)
	}
	r, err := f.c.Handle(context.Background(), f.delivery)
	if err != nil || r.Outcome != Acknowledged || f.processor.calls != 1 || f.processor.authorizations != 2 || f.broker.acks != 2 {
		t.Fatalf("duplicate: %#v %v", r, err)
	}
}

func TestPermanentDirectDLQ(t *testing.T) {
	tests := map[string]func(*queueFixture){
		"malformed":           func(f *queueFixture) { f.delivery.Fields = Fields{"raw_payload": "secret-sample"} },
		"missing":             func(f *queueFixture) { delete(f.delivery.Fields, "ref") },
		"invalid_reference":   func(f *queueFixture) { f.delivery.Fields["ref"] = "person@example.com" },
		"unsupported_schema":  func(f *queueFixture) { f.delivery.Fields["schema"] = "other" },
		"unsupported_version": func(f *queueFixture) { f.delivery.Fields["version"] = "other" },
		"missing_body":        func(f *queueFixture) { f.delivery.Invalid = true },
		"authorization":       func(f *queueFixture) { f.processor.authErr = authorization.ErrDenied },
		"validation":          func(f *queueFixture) { f.processor.err = authorization.ErrState },
		"invalid_tenant":      func(f *queueFixture) { f.processor.authErr = ErrDenied },
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			f := newQueueFixture(t)
			setup(f)
			r, err := f.c.Handle(context.Background(), f.delivery)
			if err != nil || r.Outcome != DeadLettered || r.Failure.Class != Permanent || len(f.broker.letters) != 1 || f.broker.acks != 1 {
				t.Fatalf("direct dlq: %#v %v", r, err)
			}
			if r.Attempts > 1 {
				t.Fatal("permanent retry")
			}
			if strings.Contains(f.log.String(), "secret-sample") || strings.Contains(f.log.String(), "person@example.com") {
				t.Fatal("unsafe audit")
			}
		})
	}
}

func TestBoundedRetryAndServerBudget(t *testing.T) {
	for name, cause := range map[string]error{"unavailable": ErrUnavailable, "timeout": context.DeadlineExceeded, "interrupted": context.Canceled, "unknown": errors.New("redis password=SECRET"), "kms": encryption.ErrUnavailable, "corrupt_kms": encryption.ErrCorruptResponse} {
		t.Run(name, func(t *testing.T) {
			f := newQueueFixture(t)
			f.processor.err = cause
			for attempt := uint32(1); attempt <= 3; attempt++ {
				r, err := f.c.Handle(context.Background(), f.delivery)
				if r.Attempts != attempt {
					t.Fatalf("attempt %d: %#v", attempt, r)
				}
				if attempt < 3 {
					if !errors.Is(err, ErrDeferred) || r.Outcome != Deferred || f.broker.acks != 0 || len(f.broker.letters) != 0 {
						t.Fatal("early terminal")
					}
					_, again := f.c.Handle(context.Background(), f.delivery)
					if !errors.Is(again, ErrDeferred) || f.processor.calls != int(attempt) {
						t.Fatal("backoff bypass")
					}
					f.now = f.now.Add(time.Second)
				} else if err != nil || r.Outcome != DeadLettered {
					t.Fatalf("budget terminal: %#v %v", r, err)
				}
			}
			if f.processor.calls != 3 || len(f.broker.letters) != 1 || f.broker.acks != 1 {
				t.Fatal("not bounded")
			}
			_, err := f.c.Handle(context.Background(), f.delivery)
			if err != nil || f.processor.calls != 3 || len(f.broker.letters) != 1 {
				t.Fatal("terminal reprocessing")
			}
			if strings.Contains(f.log.String(), "SECRET") {
				t.Fatal("raw error logged")
			}
		})
	}
	t.Run("payload_counter_rejected", func(t *testing.T) {
		f := newQueueFixture(t)
		f.delivery.Fields["attempts"] = "0"
		r, e := f.c.Handle(context.Background(), f.delivery)
		if e != nil || r.Outcome != DeadLettered || f.processor.calls != 0 {
			t.Fatal("payload budget accepted")
		}
	})
	t.Run("redis_counter_ignored", func(t *testing.T) {
		f := newQueueFixture(t)
		f.processor.err = ErrUnavailable
		f.broker.pending = []Pending{{ID: f.delivery.ID, Idle: time.Second, Deliveries: 999999}}
		f.broker.claimed = []Delivery{f.delivery}
		r, e := f.c.Recover(context.Background(), 1, time.Millisecond)
		if !errors.Is(e, ErrDeferred) || r[0].Attempts != 1 {
			t.Fatal("transport counter used")
		}
	})
}

func TestDLQFailureNeverPrematureACK(t *testing.T) {
	for _, cause := range []error{ErrUnavailable, ErrPermission, ErrProtocol, errors.New("WRONGTYPE password=SECRET")} {
		t.Run(fmt.Sprint(Classify(cause).Reason), func(t *testing.T) {
			f := newQueueFixture(t)
			f.delivery.Invalid = true
			f.broker.dlqErr = cause
			_, err := f.c.Handle(context.Background(), f.delivery)
			if !errors.Is(err, ErrDLQ) || f.broker.acks != 0 {
				t.Fatal("premature ACK")
			}
			f.broker.dlqErr = nil
			r, err := f.c.Handle(context.Background(), f.delivery)
			if err != nil || r.Outcome != DeadLettered || len(f.broker.letters) != 1 || f.broker.acks != 1 {
				t.Fatal("DLQ recovery failed")
			}
			if strings.Join(f.broker.commands, ",") != "dlq,dlq,ack" {
				t.Fatal("wrong transition ordering")
			}
		})
	}
}

func TestACKFailureRecoveryNeverRepeatsOperationOrDLQ(t *testing.T) {
	for _, dlq := range []bool{false, true} {
		t.Run(fmt.Sprint(dlq), func(t *testing.T) {
			f := newQueueFixture(t)
			f.delivery.Invalid = dlq
			f.broker.ackErr = errors.New("SECRET")
			_, err := f.c.Handle(context.Background(), f.delivery)
			if !errors.Is(err, ErrACK) {
				t.Fatal("ACK failure")
			}
			// New consumer instance shares only the injected durable-for-test store.
			copyConsumer, err := NewConsumer(f.c.config)
			if err != nil {
				t.Fatal(err)
			}
			f.broker.ackErr = nil
			r, err := copyConsumer.Handle(context.Background(), f.delivery)
			if err != nil {
				t.Fatal(err)
			}
			if dlq {
				if r.Outcome != DeadLettered || len(f.broker.letters) != 1 || f.processor.calls != 0 {
					t.Fatal("DLQ rewritten")
				}
			} else if r.Outcome != Acknowledged || f.processor.calls != 1 {
				t.Fatal("operation repeated")
			}
		})
	}
}

func TestCompletionRecoveryStillFreshAuthorization(t *testing.T) {
	f := newQueueFixture(t)
	f.broker.ackErr = ErrUnavailable
	_, err := f.c.Handle(context.Background(), f.delivery)
	if !errors.Is(err, ErrACK) {
		t.Fatal(err)
	}
	f.broker.ackErr = nil
	f.processor.authErr = ErrDenied
	r, err := f.c.Handle(context.Background(), f.delivery)
	if err != nil || r.Outcome != DeadLettered || r.Failure.Reason != Denied || f.processor.calls != 1 {
		t.Fatal("cached completion bypassed fresh policy")
	}
}

func TestCompletedRecoveryPDPFailuresAreBounded(t *testing.T) {
	for _, limit := range []uint32{1, 3} {
		for name, cause := range map[string]error{"dependency": authorization.ErrDependency, "unknown": errors.New("PDP credential=SECRET")} {
			t.Run(fmt.Sprintf("%s_limit_%d", name, limit), func(t *testing.T) {
				f := newQueueFixture(t)
				f.c.config.Retry.MaxAttempts = limit
				f.broker.ackErr = ErrUnavailable
				if _, err := f.c.Handle(context.Background(), f.delivery); !errors.Is(err, ErrACK) {
					t.Fatal("completion fixture did not reach failed ACK")
				}
				f.broker.ackErr = nil
				f.processor.authErr = cause
				for {
					r, err := f.c.Handle(context.Background(), f.delivery)
					if r.Outcome == DeadLettered {
						if err != nil || r.Attempts != limit || len(f.broker.letters) != 1 {
							t.Fatalf("terminal recovery: %+v %v", r, err)
						}
						break
					}
					if !errors.Is(err, ErrDeferred) || r.Attempts >= limit {
						t.Fatalf("unbounded recovery: %+v %v", r, err)
					}
					before := f.processor.authorizations
					if _, err := f.c.Handle(context.Background(), f.delivery); !errors.Is(err, ErrDeferred) || f.processor.authorizations != before {
						t.Fatal("completed recovery bypassed persisted backoff")
					}
					f.now = f.now.Add(time.Second)
				}
				if f.processor.calls != 1 || strings.Contains(f.log.String(), "SECRET") {
					t.Fatal("recovery re-executed work or leaked error")
				}
			})
		}
	}
}

func TestUnverifiedWorkerCannotTouchQueueControl(t *testing.T) {
	f := newQueueFixture(t)
	f.processor.verifyErr = ErrDenied
	f.delivery.Invalid = true
	if _, err := f.c.Handle(context.Background(), f.delivery); Classify(err) != (Classification{Permanent, Denied}) {
		t.Fatal("unverified poison-message access")
	}
	if _, err := f.c.Consume(context.Background(), 1); Classify(err) != (Classification{Permanent, Denied}) {
		t.Fatal("unverified read access")
	}
	if _, err := f.c.Recover(context.Background(), 1, time.Second); Classify(err) != (Classification{Permanent, Denied}) {
		t.Fatal("unverified claim access")
	}
	if f.broker.acks != 0 || len(f.broker.letters) != 0 || len(f.broker.commands) != 0 || len(f.store.items) != 0 {
		t.Fatal("unverified worker touched delivery state")
	}
}

func TestConcurrentDuplicateDeliveryDoesNotRepeatProcessing(t *testing.T) {
	f := newQueueFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := f.c.Handle(context.Background(), f.delivery); err != nil || r.Outcome != Acknowledged {
				t.Errorf("duplicate: %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	if f.processor.calls != 1 || f.processor.authorizations != 8 || f.broker.acks != 8 {
		t.Fatal("concurrent duplicate re-execution")
	}
}

func TestStoreFailureAndUncertainCompletion(t *testing.T) {
	t.Run("attempt_must_persist", func(t *testing.T) {
		f := newQueueFixture(t)
		f.store.saveErr = func(s State) error {
			if s.Attempts > 0 {
				return errors.New("storage SECRET")
			}
			return nil
		}
		_, e := f.c.Handle(context.Background(), f.delivery)
		if !errors.Is(e, ErrStore) || f.processor.calls != 0 || f.broker.acks != 0 {
			t.Fatal("work before attempt persistence")
		}
	})
	t.Run("completion_write_failure", func(t *testing.T) {
		f := newQueueFixture(t)
		f.store.saveErr = func(s State) error {
			if s.Phase == Completed {
				return ErrStore
			}
			return nil
		}
		_, e := f.c.Handle(context.Background(), f.delivery)
		if !errors.Is(e, ErrStore) || f.processor.calls != 1 || f.broker.acks != 0 {
			t.Fatal("completion prematurely ACKed")
		}
		// Models one-shot PEP denial on uncertain committed execution, not an
		// invented receipt protocol or approval reset.
		f.store.saveErr = nil
		f.processor.err = authorization.ErrDenied
		r, e := f.c.Handle(context.Background(), f.delivery)
		if e != nil || r.Outcome != DeadLettered || r.Failure.Reason != Denied {
			t.Fatal("uncertain result unsafe")
		}
	})
	t.Run("corrupt_state", func(t *testing.T) {
		f := newQueueFixture(t)
		k, _ := f.broker.Key(f.delivery.ID)
		l, _ := f.store.Acquire(context.Background(), k)
		_ = l.Save(context.Background(), State{Attempts: 100})
		_ = l.Release(context.Background())
		_, e := f.c.Handle(context.Background(), f.delivery)
		if !errors.Is(e, ErrStore) || f.processor.calls != 0 || f.broker.acks != 0 {
			t.Fatal("corrupt accounting accepted")
		}
	})
}

func TestMetadataSwappingCannotReuseCompletedState(t *testing.T) {
	f := newQueueFixture(t)
	_, e := f.c.Handle(context.Background(), f.delivery)
	if e != nil {
		t.Fatal(e)
	}
	f.delivery.Fields["ref"] = "abcdef0123456789abcdef0123456789"
	r, e := f.c.Handle(context.Background(), f.delivery)
	if e != nil || r.Outcome != DeadLettered || r.Failure.Reason != Denied || f.processor.calls != 1 {
		t.Fatal("source record rebound")
	}
}

func TestNoRawMessageOrErrorInDLQAudit(t *testing.T) {
	f := newQueueFixture(t)
	f.delivery.Fields = Fields{"secret": "DEK-SECRET", "payload": "RAW-SAMPLE", "token": "Bearer TOKEN", "email": "person@example.com"}
	r, e := f.c.Handle(context.Background(), f.delivery)
	if e != nil || r.Outcome != DeadLettered {
		t.Fatal(e)
	}
	combined := fmt.Sprint(f.broker.letters) + f.log.String()
	for _, secret := range []string{"DEK-SECRET", "RAW-SAMPLE", "Bearer TOKEN", "person@example.com"} {
		if strings.Contains(combined, secret) {
			t.Fatal("leaked", secret)
		}
	}
}

func TestRecoveryRechecksAuthorization(t *testing.T) {
	f := newQueueFixture(t)
	f.processor.authErr = ErrDenied
	f.broker.pending = []Pending{{ID: "1-0", Consumer: "previous-worker", Idle: time.Minute, Deliveries: 99}}
	f.broker.claimed = []Delivery{f.delivery}
	r, e := f.c.Recover(context.Background(), 1, time.Second)
	if e != nil || len(r) != 1 || r[0].Outcome != DeadLettered || f.processor.calls != 0 || f.processor.authorizations != 1 {
		t.Fatal("claim bypassed policy")
	}
}

type failedAuditWriter struct{}

func (failedAuditWriter) Write([]byte) (int, error) { return 0, errors.New("audit password=SECRET") }
func TestAuditFailureLeavesPending(t *testing.T) {
	f := newQueueFixture(t)
	f.c.config.Audit = audit.New(failedAuditWriter{}, "event")
	_, e := f.c.Handle(context.Background(), f.delivery)
	if !errors.Is(e, ErrAudit) || f.processor.calls != 0 || f.broker.acks != 0 {
		t.Fatal("audit failure bypass")
	}
}

func TestRequiredConfigurationNoDefaults(t *testing.T) {
	f := newQueueFixture(t)
	for _, modify := range []func(*ConsumerConfig){func(c *ConsumerConfig) { c.Retry.MaxAttempts = 0 }, func(c *ConsumerConfig) { c.Retry.Backoff = nil }, func(c *ConsumerConfig) { c.Store = nil }, func(c *ConsumerConfig) { c.Processor = nil }, func(c *ConsumerConfig) { c.Audit = nil }, func(c *ConsumerConfig) { c.Schema = nil }, func(c *ConsumerConfig) { c.Broker = nil }} {
		c := f.c.config
		modify(&c)
		if _, e := NewConsumer(c); !errors.Is(e, ErrConfiguration) {
			t.Fatal("missing config accepted")
		}
	}
	f.processor.err = ErrUnavailable
	f.c.config.Retry.Backoff = func(uint32) time.Duration { return -time.Second }
	_, e := f.c.Handle(context.Background(), f.delivery)
	if !errors.Is(e, ErrConfiguration) || f.broker.acks != 0 {
		t.Fatal("negative backoff")
	}
}

func TestSchemaRejectsExtraSecretFieldsAndHasNoDefault(t *testing.T) {
	if _, e := NewSchema(SchemaConfig{}); !errors.Is(e, ErrConfiguration) {
		t.Fatal("schema default")
	}
	f := newQueueFixture(t)
	for _, field := range []string{"tenant_id", "worker", "approval", "retry_limit", "payload", "token", "credential", "plaintext_dek", "pii"} {
		t.Run(field, func(t *testing.T) {
			copyFields := Fields{}
			for k, v := range f.delivery.Fields {
				copyFields[k] = v
			}
			copyFields[field] = "SECRET"
			if _, e := f.schema.Decode(copyFields); !errors.Is(e, ErrMalformed) {
				t.Fatal("extra field accepted")
			}
		})
	}
}

func TestSafeFailureClassification(t *testing.T) {
	for _, c := range []Classification{{Permanent, Malformed}, {Permanent, Unsupported}, {Permanent, Denied}, {Permanent, Validation}, {Transient, Unavailable}, {Transient, Timeout}, {Transient, Interrupted}, {Transient, Dependency}, {Unknown, Unclassified}} {
		if got := Classify(c); got != c {
			t.Fatalf("%#v", got)
		}
	}
	if c := Classify(Classification{Class: "SECRET", Reason: "raw-error"}); c != (Classification{Unknown, Unclassified}) {
		t.Fatal("unsafe classification")
	}
	if c := Classify(errors.New("Bearer SECRET")); c != (Classification{Unknown, Unclassified}) || strings.Contains(c.Error(), "SECRET") {
		t.Fatal("unsafe unknown")
	}
}
