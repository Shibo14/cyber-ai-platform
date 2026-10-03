package redis

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/queue"
)

// Test-only progress storage deliberately makes no production persistence or
// idempotency schema choice. Fixtures share it across consumer recreation to
// exercise the injected Store contract and transport recovery.
type fixtureStore struct {
	mu     sync.Mutex
	states map[queue.DeliveryKey]queue.State
}
type fixtureLease struct {
	store *fixtureStore
	key   queue.DeliveryKey
}

func (s *fixtureStore) Acquire(_ context.Context, key queue.DeliveryKey) (queue.Lease, error) {
	s.mu.Lock()
	return &fixtureLease{s, key}, nil
}
func (l *fixtureLease) Load(context.Context) (queue.State, error) { return l.store.states[l.key], nil }
func (l *fixtureLease) Save(_ context.Context, state queue.State) error {
	l.store.states[l.key] = state
	return nil
}
func (l *fixtureLease) Release(context.Context) error { l.store.mu.Unlock(); return nil }

// This trusted test Processor is for transport tests only. Production wiring
// must use the reviewed PEP/encryption adapter, tested separately.
type fixtureProcessor struct {
	authorizations, calls int
	deny, failure         error
	authFailure           error
}

func (p *fixtureProcessor) VerifyWorker(context.Context) error { return p.deny }
func (p *fixtureProcessor) Authorize(context.Context, queue.Metadata) error {
	p.authorizations++
	if p.authFailure != nil {
		return p.authFailure
	}
	return p.deny
}
func (p *fixtureProcessor) Process(context.Context, queue.Metadata) error {
	p.calls++
	return p.failure
}

type faultCommander struct {
	base     Commander
	command  string
	failures int
	err      error
}

func (f *faultCommander) Do(ctx context.Context, args ...any) (any, error) {
	if len(args) > 0 && args[0] == f.command && f.failures > 0 {
		f.failures--
		return nil, f.err
	}
	return f.base.Do(ctx, args...)
}

func realAdapter(t *testing.T) (*Adapter, *respCommander) {
	t.Helper()
	commander := realCommander(t)
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "cyb15-test:" + hex.EncodeToString(random[:])
	config := fixtureConfig(t, commander)
	config.Stream, config.Group, config.Consumer, config.DLQ = prefix+":stream", prefix+":group", prefix+":consumer", prefix+":dlq"
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.CreateGroup(context.Background(), "0", true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = commander.Do(context.Background(), "DEL", config.Stream, config.DLQ) })
	return adapter, commander
}

func realConsumer(t *testing.T, adapter *Adapter, processor *fixtureProcessor, store *fixtureStore, output *bytes.Buffer, attempts uint32) *queue.Consumer {
	t.Helper()
	consumer, err := queue.NewConsumer(queue.ConsumerConfig{Broker: adapter, Schema: adapter.config.Schema, Processor: processor, Store: store,
		Retry: queue.RetryPolicy{MaxAttempts: attempts, Backoff: func(uint32) time.Duration { return 0 }},
		Audit: audit.New(output, "event", "outcome", "failure_class", "reason", "attempts")})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func freshStore() *fixtureStore { return &fixtureStore{states: map[queue.DeliveryKey]queue.State{}} }

func pendingCount(t *testing.T, adapter *Adapter, count int) {
	t.Helper()
	entries, err := adapter.PendingRange(context.Background(), "-", "+", 10)
	if err != nil || len(entries) != count {
		t.Fatalf("pending count: got %d want %d err %v", len(entries), count, err)
	}
}

func streamLength(t *testing.T, commander Commander, key string) int64 {
	t.Helper()
	value, err := commander.Do(context.Background(), "XLEN", key)
	if err != nil {
		t.Fatal("test stream length failed")
	}
	n, ok := value.(int64)
	if !ok {
		t.Fatal("invalid test stream length")
	}
	return n
}

func idlePending(t *testing.T, adapter *Adapter, commander Commander, id string) {
	t.Helper()
	if _, err := commander.Do(context.Background(), "XCLAIM", adapter.config.Stream, adapter.config.Group, adapter.config.Consumer, int64(0), id, "IDLE", int64(100)); err != nil {
		t.Fatal("test could not age pending delivery")
	}
}

func TestRealRedisProduceConsumeCompletionACKAndDuplicate(t *testing.T) {
	adapter, _ := realAdapter(t)
	ctx := context.Background()
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	processor, store, output := &fixtureProcessor{}, freshStore(), &bytes.Buffer{}
	consumer := realConsumer(t, adapter, processor, store, output, 2)
	results, err := consumer.Consume(ctx, 10)
	if err != nil || len(results) != 1 || results[0].Outcome != queue.Acknowledged || processor.calls != 1 {
		t.Fatalf("completion flow failed: %#v %v calls=%d", results, err, processor.calls)
	}
	pendingCount(t, adapter, 0)
	// Duplicate delivery retains its same transport ID and must only revalidate
	// authority and ACK; it must not repeat protected processing.
	result, err := consumer.Handle(ctx, queue.Delivery{ID: id, Fields: fixtureFields(t, adapter)})
	if err != nil || result.Outcome != queue.Acknowledged || processor.calls != 1 || processor.authorizations != 2 {
		t.Fatalf("duplicate repeated processing: %#v %v calls=%d auth=%d", result, err, processor.calls, processor.authorizations)
	}
}

func TestRealRedisPendingClaimRecovery(t *testing.T) {
	adapter, commander := realAdapter(t)
	ctx := context.Background()
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Read(ctx, 1); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, adapter, 1)
	idlePending(t, adapter, commander, id)
	config := adapter.config
	config.Consumer += "-recovered"
	recovered, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	processor, output := &fixtureProcessor{}, &bytes.Buffer{}
	consumer := realConsumer(t, recovered, processor, freshStore(), output, 2)
	results, err := consumer.Recover(ctx, 1, time.Millisecond)
	if err != nil || len(results) != 1 || results[0].Outcome != queue.Acknowledged || processor.calls != 1 {
		t.Fatalf("pending recovery failed: %#v %v", results, err)
	}
	pendingCount(t, adapter, 0)
}

func TestRealRedisMalformedUnsupportedAndSecretProjection(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(fmt.Sprintf("unsupported=%v", unsupported), func(t *testing.T) {
			adapter, commander := realAdapter(t)
			ctx := context.Background()
			marker := "token=SECRET raw-sample plaintext-DEK person@example.test"
			var args []any
			if unsupported {
				args = []any{"s", "fixture", "v", "unknown-version", "r", fixtureReference}
			} else {
				// Simulate a hostile external writer. The producer itself rejects
				// such fields; the consumer must not copy this poison body onward.
				args = []any{"raw_payload", marker}
			}
			if _, err := commander.Do(ctx, append([]any{"XADD", adapter.config.Stream, "*"}, args...)...); err != nil {
				t.Fatal("fixture publish failed")
			}
			processor, output := &fixtureProcessor{}, &bytes.Buffer{}
			consumer := realConsumer(t, adapter, processor, freshStore(), output, 3)
			results, err := consumer.Consume(ctx, 1)
			if err != nil || len(results) != 1 || results[0].Outcome != queue.DeadLettered || processor.calls != 0 {
				t.Fatalf("permanent flow failed: %#v %v", results, err)
			}
			want := queue.Malformed
			if unsupported {
				want = queue.Unsupported
			}
			if results[0].Failure.Reason != want {
				t.Fatal("wrong permanent classification")
			}
			pendingCount(t, adapter, 0)
			dlq, err := commander.Do(ctx, "XRANGE", adapter.config.DLQ, "-", "+")
			if err != nil || strings.Contains(fmt.Sprint(dlq), marker) || strings.Contains(output.String(), marker) || strings.Contains(fmt.Sprint(dlq), fixtureReference) {
				t.Fatal("secret/reference copied into DLQ or audit")
			}
			if streamLength(t, commander, adapter.config.DLQ) != 1 {
				t.Fatal("missing dead letter")
			}
		})
	}
}

func TestRealRedisTransientAndUnknownBoundedRetry(t *testing.T) {
	for _, failure := range []error{queue.ErrUnavailable, errors.New("raw SDK credential error")} {
		adapter, commander := realAdapter(t)
		ctx := context.Background()
		if _, err := adapter.Publish(ctx, fixtureFields(t, adapter)); err != nil {
			t.Fatal(err)
		}
		processor, output := &fixtureProcessor{failure: failure}, &bytes.Buffer{}
		consumer := realConsumer(t, adapter, processor, freshStore(), output, 2)
		results, err := consumer.Consume(ctx, 1)
		if !errors.Is(err, queue.ErrDeferred) || len(results) != 1 || results[0].Attempts != 1 {
			t.Fatalf("first retry failed: %#v %v", results, err)
		}
		pendingCount(t, adapter, 1)
		entries, err := adapter.ReadPending(ctx, 1)
		if err != nil || len(entries) != 1 {
			t.Fatal("retry pending delivery missing")
		}
		result, err := consumer.Handle(ctx, entries[0])
		if err != nil || result.Outcome != queue.DeadLettered || result.Attempts != 2 || processor.calls != 2 {
			t.Fatalf("bounded exhaustion failed: %#v %v", result, err)
		}
		pendingCount(t, adapter, 0)
		if streamLength(t, commander, adapter.config.DLQ) != 1 {
			t.Fatal("retry exhaustion missing DLQ")
		}
		if strings.Contains(output.String(), "credential") {
			t.Fatal("raw error leaked into audit")
		}
	}
}

func TestRealRedisDLQFailureLeavesSourcePending(t *testing.T) {
	for _, mode := range []string{"wrong-type", "unavailable", "permission-denied"} {
		t.Run(mode, func(t *testing.T) {
			adapter, commander := realAdapter(t)
			ctx := context.Background()
			if _, err := adapter.Publish(ctx, fixtureFields(t, adapter)); err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-type" {
				if _, err := commander.Do(ctx, "SET", adapter.config.DLQ, "fixture"); err != nil {
					t.Fatal("fixture wrong type failed")
				}
			} else if mode == "unavailable" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := listener.Addr().String()
				_ = listener.Close()
				adapter.config.Commander = &routeDLQCommander{base: commander, dlq: adapter.config.DLQ, failing: &respCommander{address: address}}
			} else {
				username := strings.ReplaceAll(adapter.config.Group, ":", "_")
				password := "fixture-only-not-production"
				// The test user can process only this source stream and cannot
				// write the DLQ key. These are fixture ACLs, not a deployment choice.
				if _, err := commander.Do(ctx, "ACL", "SETUSER", username, "on", ">"+password, "~"+adapter.config.Stream, "+xreadgroup", "+xadd", "+xack", "+xpending", "+xclaim"); err != nil {
					t.Fatal("test Redis requires ACL setup permission")
				}
				t.Cleanup(func() { _, _ = commander.Do(context.Background(), "ACL", "DELUSER", username) })
				adapter.config.Commander = &respCommander{address: commander.address, username: username, password: password}
			}
			processor, output := &fixtureProcessor{failure: queue.ErrValidation}, &bytes.Buffer{}
			consumer := realConsumer(t, adapter, processor, freshStore(), output, 2)
			results, err := consumer.Consume(ctx, 1)
			if !errors.Is(err, queue.ErrDLQ) || len(results) != 1 || results[0].Outcome != queue.Unconfirmed {
				t.Fatalf("DLQ failure was not safe: %#v %v", results, err)
			}
			// Observe with the unrestricted test commander; the source must
			// still be pending after any DLQ dependency failure.
			checkConfig := adapter.config
			checkConfig.Commander = commander
			check, err := New(checkConfig)
			if err != nil {
				t.Fatal(err)
			}
			pendingCount(t, check, 1)
		})
	}
}

type routeDLQCommander struct {
	base, failing Commander
	dlq           string
}

func (r *routeDLQCommander) Do(ctx context.Context, args ...any) (any, error) {
	if len(args) > 1 && args[0] == "XADD" && args[1] == r.dlq {
		return r.failing.Do(ctx, args...)
	}
	return r.base.Do(ctx, args...)
}

func TestRealRedisCompletionThenACKFailureRecovery(t *testing.T) {
	adapter, commander := realAdapter(t)
	ctx := context.Background()
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	adapter.config.Commander = &faultCommander{base: commander, command: "XACK", failures: 1, err: errors.New("raw ACK credential error")}
	processor, output, store := &fixtureProcessor{}, &bytes.Buffer{}, freshStore()
	consumer := realConsumer(t, adapter, processor, store, output, 2)
	results, err := consumer.Consume(ctx, 1)
	if !errors.Is(err, queue.ErrACK) || len(results) != 1 || processor.calls != 1 {
		t.Fatalf("ACK failure fixture failed: %#v %v", results, err)
	}
	pendingCount(t, adapter, 1)
	idlePending(t, adapter, commander, id)
	// Recreate consumer to exercise the shared progress-store contract.
	consumer = realConsumer(t, adapter, processor, store, output, 2)
	results, err = consumer.Recover(ctx, 1, time.Millisecond)
	if err != nil || len(results) != 1 || results[0].Outcome != queue.Acknowledged || processor.calls != 1 || processor.authorizations != 2 {
		t.Fatalf("completion replayed operation: %#v %v calls=%d", results, err, processor.calls)
	}
	pendingCount(t, adapter, 0)
}

func TestRealRedisDLQSuccessACKFailureRecoveryDoesNotRewrite(t *testing.T) {
	adapter, commander := realAdapter(t)
	ctx := context.Background()
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	adapter.config.Commander = &faultCommander{base: commander, command: "XACK", failures: 1, err: queue.ErrUnavailable}
	processor, output, store := &fixtureProcessor{failure: queue.ErrValidation}, &bytes.Buffer{}, freshStore()
	consumer := realConsumer(t, adapter, processor, store, output, 2)
	if _, err := consumer.Consume(ctx, 1); !errors.Is(err, queue.ErrACK) {
		t.Fatal("expected source ACK failure")
	}
	if streamLength(t, commander, adapter.config.DLQ) != 1 {
		t.Fatal("DLQ write not confirmed before ACK")
	}
	pendingCount(t, adapter, 1)
	idlePending(t, adapter, commander, id)
	consumer = realConsumer(t, adapter, processor, store, output, 2)
	results, err := consumer.Recover(ctx, 1, time.Millisecond)
	if err != nil || len(results) != 1 || results[0].Outcome != queue.DeadLettered || processor.calls != 1 {
		t.Fatalf("DLQ recovery repeated operation: %#v %v", results, err)
	}
	if streamLength(t, commander, adapter.config.DLQ) != 1 {
		t.Fatal("confirmed DLQ rewritten after ACK failure")
	}
	pendingCount(t, adapter, 0)
}

func TestRealRedisProducerCannotWritePayloadOrAuthority(t *testing.T) {
	adapter, commander := realAdapter(t)
	for _, field := range []string{"payload", "tenant_id", "worker", "approval", "token", "plaintext_dek", "retry_budget", "email"} {
		fields := fixtureFields(t, adapter)
		fields[field] = "secret@example.test"
		if _, err := adapter.Publish(context.Background(), fields); err != queue.ErrMalformed {
			t.Fatal("arbitrary field accepted")
		}
	}
	if streamLength(t, commander, adapter.config.Stream) != 0 {
		t.Fatal("prohibited data reached source stream")
	}
}

func TestRealRedisRecoveryPagesPastRecentPendingEntry(t *testing.T) {
	adapter, commander := realAdapter(t)
	ctx := context.Background()
	first, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Read(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := commander.Do(ctx, "XCLAIM", adapter.config.Stream, adapter.config.Group, adapter.config.Consumer, int64(0), second, "IDLE", int64(1000)); err != nil {
		t.Fatal("fixture aging failed")
	}
	if _, err := commander.Do(ctx, "XCLAIM", adapter.config.Stream, adapter.config.Group, adapter.config.Consumer, int64(0), first, "IDLE", int64(0)); err != nil {
		t.Fatal("fixture aging failed")
	}
	processor, output := &fixtureProcessor{}, &bytes.Buffer{}
	consumer := realConsumer(t, adapter, processor, freshStore(), output, 2)
	results, err := consumer.Recover(ctx, 1, 500*time.Millisecond)
	if err != nil || len(results) != 0 {
		t.Fatalf("recent first entry unexpectedly processed: %#v %v", results, err)
	}
	results, err = consumer.Recover(ctx, 1, 500*time.Millisecond)
	if err != nil || len(results) != 1 || results[0].Outcome != queue.Acknowledged || processor.calls != 1 {
		t.Fatalf("eligible later entry starved: %#v %v", results, err)
	}
	remaining, err := adapter.PendingRange(ctx, "-", "+", 10)
	if err != nil || len(remaining) != 1 || remaining[0].ID != first {
		t.Fatalf("wrong recovery target: %#v %v", remaining, err)
	}
}

func TestRealRedisCompletedRecoveryPDPFailuresBounded(t *testing.T) {
	adapter, commander := realAdapter(t)
	ctx := context.Background()
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil {
		t.Fatal(err)
	}
	adapter.config.Commander = &faultCommander{base: commander, command: "XACK", failures: 1, err: queue.ErrUnavailable}
	processor := &fixtureProcessor{}
	consumer := realConsumer(t, adapter, processor, freshStore(), &bytes.Buffer{}, 3)
	if _, err := consumer.Consume(ctx, 1); !errors.Is(err, queue.ErrACK) {
		t.Fatal("expected completion ACK failure")
	}
	processor.authFailure = queue.ErrDependency
	idlePending(t, adapter, commander, id)
	r, err := consumer.Recover(ctx, 1, time.Millisecond)
	if !errors.Is(err, queue.ErrDeferred) || len(r) != 1 || r[0].Attempts != 2 {
		t.Fatalf("first recovery: %+v %v", r, err)
	}
	pendingCount(t, adapter, 1)
	idlePending(t, adapter, commander, id)
	r, err = consumer.Recover(ctx, 1, time.Millisecond)
	if err != nil || len(r) != 1 || r[0].Outcome != queue.DeadLettered || r[0].Attempts != 3 {
		t.Fatalf("bounded recovery: %+v %v", r, err)
	}
	if processor.calls != 1 || streamLength(t, commander, adapter.config.DLQ) != 1 {
		t.Fatal("completed operation repeated or DLQ missing")
	}
	pendingCount(t, adapter, 0)
}
