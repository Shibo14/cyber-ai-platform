package redis

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"cyber-ai-platform/internal/queue"
)

const fixtureReference = "0123456789abcdef0123456789abcdef"

type commandResult struct {
	value any
	err   error
}

type scriptedCommander struct {
	results  []commandResult
	commands [][]any
}

func (s *scriptedCommander) Do(_ context.Context, args ...any) (any, error) {
	s.commands = append(s.commands, append([]any(nil), args...))
	if len(s.results) == 0 {
		return nil, errors.New("unexpected fixture command")
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result.value, result.err
}

func fixtureSchema(t *testing.T) *queue.Schema {
	t.Helper()
	reference := regexp.MustCompile(`^[a-f0-9]{32}$`)
	schema, err := queue.NewSchema(queue.SchemaConfig{ID: "fixture", Version: "test-v1", SchemaField: "s", VersionField: "v", ReferenceField: "r", ValidReference: reference.MatchString})
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func fixtureConfig(t *testing.T, commander Commander) Config {
	t.Helper()
	return Config{Commander: commander, Stream: "fixture:stream", Group: "fixture:group", Consumer: "fixture:consumer", DLQ: "fixture:dlq", Schema: fixtureSchema(t),
		DLQFields: DLQFields{SourceID: "source", Class: "class", Reason: "reason", Attempts: "attempts"}}
}

func fixtureAdapter(t *testing.T, commander Commander) *Adapter {
	t.Helper()
	adapter, err := New(fixtureConfig(t, commander))
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func fixtureFields(t *testing.T, adapter *Adapter) queue.Fields {
	t.Helper()
	fields, err := adapter.config.Schema.Encode(adapter.config.Schema.Metadata(fixtureReference))
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func rawFixtureEntry(id string) []any {
	return []any{id, []any{"s", "fixture", "v", "test-v1", "r", fixtureReference}}
}

func rawFixtureRead(entries ...any) []any {
	return []any{[]any{"fixture:stream", entries}}
}

func TestConfiguredCommandsAndMetadataOnlyWrites(t *testing.T) {
	ctx := context.Background()
	commander := &scriptedCommander{results: []commandResult{
		{value: "OK"}, {value: "100-0"}, {value: rawFixtureRead(rawFixtureEntry("100-0"))},
		{value: []any{[]any{"100-0", "old-consumer", int64(120), int64(8)}}},
		{value: []any{rawFixtureEntry("100-0")}}, {value: int64(1)}, {value: "101-0"},
	}}
	adapter := fixtureAdapter(t, commander)
	if err := adapter.CreateGroup(ctx, "0", true); err != nil {
		t.Fatal(err)
	}
	id, err := adapter.Publish(ctx, fixtureFields(t, adapter))
	if err != nil || id != "100-0" {
		t.Fatalf("publish: id=%q err=%v", id, err)
	}
	key, err := adapter.Key(id)
	if err != nil || key != (queue.DeliveryKey{Stream: "fixture:stream", Group: "fixture:group", ID: id}) {
		t.Fatalf("wrong trusted delivery key: %#v %v", key, err)
	}
	entries, err := adapter.Read(ctx, 3)
	if err != nil || len(entries) != 1 || entries[0].Invalid || entries[0].Fields["r"] != fixtureReference {
		t.Fatalf("read: %#v %v", entries, err)
	}
	pending, err := adapter.Pending(ctx, 3)
	if err != nil || len(pending) != 1 || pending[0].Idle != 120*time.Millisecond || pending[0].Deliveries != 8 {
		t.Fatalf("pending: %#v %v", pending, err)
	}
	claimed, err := adapter.Claim(ctx, []string{id}, 100*time.Millisecond)
	if err != nil || len(claimed) != 1 || claimed[0].Invalid {
		t.Fatalf("claim: %#v %v", claimed, err)
	}
	if err := adapter.Ack(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.WriteDLQ(ctx, queue.DeadLetter{SourceID: id, Class: queue.Permanent, Reason: queue.Malformed}); err != nil {
		t.Fatal(err)
	}
	want := [][]any{
		{"XGROUP", "CREATE", "fixture:stream", "fixture:group", "0", "MKSTREAM"},
		{"XADD", "fixture:stream", "*", "r", fixtureReference, "s", "fixture", "v", "test-v1"},
		{"XREADGROUP", "GROUP", "fixture:group", "fixture:consumer", "COUNT", int64(3), "STREAMS", "fixture:stream", ">"},
		{"XPENDING", "fixture:stream", "fixture:group", "-", "+", int64(3)},
		{"XCLAIM", "fixture:stream", "fixture:group", "fixture:consumer", int64(100), "100-0"},
		{"XACK", "fixture:stream", "fixture:group", "100-0"},
		{"XADD", "fixture:dlq", "*", "attempts", "0", "class", "permanent", "reason", "malformed", "source", "100-0"},
	}
	if !reflect.DeepEqual(commander.commands, want) {
		t.Fatalf("commands differ: got %#v", commander.commands)
	}
}

func TestMalformedBodiesRetainOnlySourceID(t *testing.T) {
	marker := "credential-plaintext-DEK-raw-sample@example.test"
	cases := map[string]any{
		"missing body":           nil,
		"empty body":             []any{},
		"odd fields":             []any{"s", "fixture", "token"},
		"duplicate fields":       []any{"s", "fixture", "s", marker},
		"nonstring value":        []any{"s", []any{marker}},
		"unknown field":          []any{"s", "fixture", "v", "test-v1", "r", fixtureReference, "secret", marker},
		"missing required field": []any{"s", "fixture", "v", "test-v1"},
		"invalid reference":      []any{"s", "fixture", "v", "test-v1", "r", marker},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			commander := &scriptedCommander{results: []commandResult{{value: rawFixtureRead([]any{"100-0", fields})}}}
			adapter := fixtureAdapter(t, commander)
			entries, err := adapter.Read(context.Background(), 1)
			if err != nil || len(entries) != 1 || entries[0].ID != "100-0" || !entries[0].Invalid || entries[0].Fields != nil {
				t.Fatalf("malformed data escaped projection: %#v %v", entries, err)
			}
			if strings.Contains(fmt.Sprint(entries, err), marker) {
				t.Fatal("raw data leaked into delivery or error")
			}
		})
	}
}

func TestUnsupportedMetadataRemainsPermanentAndDistinguishable(t *testing.T) {
	commander := &scriptedCommander{results: []commandResult{{value: rawFixtureRead([]any{"100-0", []any{"s", "fixture", "v", "unsupported", "r", fixtureReference}})}}}
	adapter := fixtureAdapter(t, commander)
	entries, err := adapter.Read(context.Background(), 1)
	if err != nil || len(entries) != 1 || entries[0].Invalid {
		t.Fatalf("unsupported metadata response: %#v %v", entries, err)
	}
	if _, err := adapter.config.Schema.Decode(entries[0].Fields); err != queue.ErrUnsupported {
		t.Fatal("unsupported schema lost its safe classification")
	}
}

func TestCorruptTransportRepliesFailClosed(t *testing.T) {
	cases := map[string]any{
		"wrong outer type":       "secret-sdk-response",
		"wrong stream":           []any{[]any{"other-stream", []any{rawFixtureEntry("100-0")}}},
		"missing stream entries": []any{[]any{"fixture:stream"}},
		"bad ID":                 rawFixtureRead(rawFixtureEntry("secret-token")),
		"noncanonical ID":        rawFixtureRead(rawFixtureEntry("0100-0")),
		"entry wrong shape":      rawFixtureRead([]any{"100-0"}),
		"duplicate IDs":          rawFixtureRead(rawFixtureEntry("100-0"), rawFixtureEntry("100-0")),
		"more than requested":    rawFixtureRead(rawFixtureEntry("100-0"), rawFixtureEntry("100-1")),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			adapter := fixtureAdapter(t, &scriptedCommander{results: []commandResult{{value: response}}})
			entries, err := adapter.Read(context.Background(), 1)
			if entries != nil || !errors.Is(err, queue.ErrProtocol) {
				t.Fatalf("corrupt response not denied: %#v %v", entries, err)
			}
		})
	}
}

func TestRawDependencyErrorsAreMasked(t *testing.T) {
	marker := "redis-password=SECRET plaintext-DEK=KEY tenant@example.test"
	for _, fixture := range []struct {
		name      string
		raw, want error
	}{
		{"raw", errors.New(marker), queue.ErrDependency},
		{"permission", fmt.Errorf("%s: %w", marker, queue.ErrPermission), queue.ErrPermission},
		{"unavailable", fmt.Errorf("%s: %w", marker, queue.ErrUnavailable), queue.ErrUnavailable},
		{"timeout", fmt.Errorf("%s: %w", marker, context.DeadlineExceeded), context.DeadlineExceeded},
		{"canceled", fmt.Errorf("%s: %w", marker, context.Canceled), context.Canceled},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			adapter := fixtureAdapter(t, &scriptedCommander{results: []commandResult{{err: fixture.raw}}})
			_, err := adapter.Publish(context.Background(), fixtureFields(t, adapter))
			if err != fixture.want || strings.Contains(err.Error(), marker) || errors.Unwrap(err) != nil {
				t.Fatalf("unsafe dependency error: %v", err)
			}
		})
	}
}

func TestDLQWriteFailureNeverAcknowledgesSource(t *testing.T) {
	for _, raw := range []error{queue.ErrUnavailable, queue.ErrPermission, errors.New("WRONGTYPE secret SDK response")} {
		commander := &scriptedCommander{results: []commandResult{{err: raw}}}
		adapter := fixtureAdapter(t, commander)
		id, err := adapter.WriteDLQ(context.Background(), queue.DeadLetter{SourceID: "100-0", Class: queue.Permanent, Reason: queue.Malformed})
		if err == nil || id != "" || len(commander.commands) != 1 || commander.commands[0][0] != "XADD" {
			t.Fatalf("DLQ failure performed unsafe command: %#v %v", commander.commands, err)
		}
	}
}

func TestInvalidPublicationAndDLQRejectedBeforeRedis(t *testing.T) {
	commander := &scriptedCommander{}
	adapter := fixtureAdapter(t, commander)
	fields := fixtureFields(t, adapter)
	fields["payload"] = "raw sample secret"
	if _, err := adapter.Publish(context.Background(), fields); !errors.Is(err, queue.ErrMalformed) {
		t.Fatal("arbitrary payload accepted")
	}
	for _, letter := range []queue.DeadLetter{
		{SourceID: "invalid", Class: queue.Permanent, Reason: queue.Malformed},
		{SourceID: "100-0", Class: queue.Class("secret"), Reason: queue.Malformed},
		{SourceID: "100-0", Class: queue.Transient, Reason: queue.Denied},
	} {
		if _, err := adapter.WriteDLQ(context.Background(), letter); !errors.Is(err, queue.ErrMalformed) {
			t.Fatal("unvalidated dead letter accepted")
		}
	}
	if len(commander.commands) != 0 {
		t.Fatal("invalid publication reached Redis")
	}
}

func TestRecoveryCommandsRemainTransportOnly(t *testing.T) {
	commander := &scriptedCommander{results: []commandResult{{value: rawFixtureRead(rawFixtureEntry("100-0"))}, {value: []any{}}, {value: int64(0)}}}
	adapter := fixtureAdapter(t, commander)
	entries, err := adapter.ReadPending(context.Background(), 2)
	if err != nil || len(entries) != 1 || entries[0].Fields["r"] != fixtureReference {
		t.Fatalf("own pending: %#v %v", entries, err)
	}
	if _, err := adapter.PendingRange(context.Background(), "100-0", "+", 2); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Ack(context.Background(), "100-0"); err != nil {
		t.Fatal("idempotent transport ACK failed")
	}
	if commander.commands[0][len(commander.commands[0])-1] != "0" {
		t.Fatal("own pending recovery did not request history")
	}
	for _, command := range commander.commands {
		for _, arg := range command {
			if arg == "NOACK" || arg == "MULTI" || arg == "MAXLEN" {
				t.Fatal("unsafe or unapproved transport option")
			}
		}
	}
}

func TestCorruptPendingClaimAndACKRepliesDenied(t *testing.T) {
	for _, response := range []any{
		[]any{[]any{"100-0", "consumer", int64(-1), int64(1)}},
		[]any{[]any{"100-0", "consumer", int64(1<<63 - 1), int64(1)}},
		[]any{[]any{"100-0", "consumer", int64(0), int64(-1)}},
		[]any{[]any{"100-0", "consumer", "0", int64(1)}},
	} {
		adapter := fixtureAdapter(t, &scriptedCommander{results: []commandResult{{value: response}}})
		if _, err := adapter.Pending(context.Background(), 1); err != queue.ErrProtocol {
			t.Fatal("corrupt pending reply accepted")
		}
	}
	adapter := fixtureAdapter(t, &scriptedCommander{results: []commandResult{{value: []any{rawFixtureEntry("101-0")}}}})
	if _, err := adapter.Claim(context.Background(), []string{"100-0"}, 0); err != queue.ErrProtocol {
		t.Fatal("claim returned an unrequested source ID")
	}
	for _, response := range []any{int64(-1), int64(2), "1", nil} {
		adapter := fixtureAdapter(t, &scriptedCommander{results: []commandResult{{value: response}}})
		if err := adapter.Ack(context.Background(), "100-0"); err != queue.ErrProtocol {
			t.Fatal("corrupt ACK accepted")
		}
	}
}

func TestConfigurationAndRecoveryArgumentsRequired(t *testing.T) {
	commander := &scriptedCommander{}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Commander = nil }, func(c *Config) { c.Schema = nil },
		func(c *Config) { c.Stream = "" }, func(c *Config) { c.Group = "" },
		func(c *Config) { c.Consumer = "" }, func(c *Config) { c.DLQ = c.Stream },
		func(c *Config) { c.DLQFields.Reason = c.DLQFields.Class },
	} {
		config := fixtureConfig(t, commander)
		mutate(&config)
		if _, err := New(config); err != queue.ErrConfiguration {
			t.Fatal("invalid configuration accepted")
		}
	}
	adapter := fixtureAdapter(t, commander)
	if _, err := adapter.Read(context.Background(), 0); err != queue.ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := adapter.Pending(context.Background(), -1); err != queue.ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := adapter.Claim(context.Background(), nil, 0); err != queue.ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := adapter.Claim(context.Background(), []string{"100-0"}, time.Nanosecond); err != queue.ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := adapter.Claim(context.Background(), []string{"100-0", "100-0"}, 0); err != queue.ErrMalformed {
		t.Fatal(err)
	}
	if err := adapter.CreateGroup(context.Background(), "*", true); err != queue.ErrConfiguration {
		t.Fatal(err)
	}
	if err := adapter.Ack(context.Background(), "token"); err != queue.ErrMalformed {
		t.Fatal(err)
	}
	if len(commander.commands) != 0 {
		t.Fatal("invalid arguments reached Redis")
	}
}

func TestPendingPagingDoesNotStarveLaterEligibleEntries(t *testing.T) {
	commander := &scriptedCommander{results: []commandResult{
		{value: []any{[]any{"100-0", "consumer", int64(0), int64(1)}}},
		{value: []any{[]any{"101-0", "consumer", int64(1000), int64(1)}}},
		{value: []any{}},
		{value: []any{[]any{"100-0", "consumer", int64(0), int64(1)}}},
	}}
	adapter := fixtureAdapter(t, commander)
	first, err := adapter.Pending(context.Background(), 1)
	if err != nil || len(first) != 1 || first[0].ID != "100-0" {
		t.Fatalf("first page: %#v %v", first, err)
	}
	second, err := adapter.Pending(context.Background(), 1)
	if err != nil || len(second) != 1 || second[0].ID != "101-0" || second[0].Idle < time.Second {
		t.Fatalf("eligible second entry starved: %#v %v", second, err)
	}
	wrapped, err := adapter.Pending(context.Background(), 1)
	if err != nil || len(wrapped) != 1 || wrapped[0].ID != "100-0" {
		t.Fatalf("paging did not wrap: %#v %v", wrapped, err)
	}
	for i, start := range []string{"-", "100-1", "101-1", "-"} {
		if commander.commands[i][3] != start {
			t.Fatalf("wrong inclusive numeric successor page: %#v", commander.commands)
		}
	}
}

func TestPendingNumericSuccessorOverflowWrapsSafely(t *testing.T) {
	for id, want := range map[string]string{
		"100-0": "100-1", "100-18446744073709551615": "101-0", "18446744073709551615-18446744073709551615": "-",
	} {
		if got := successor(id); got != want {
			t.Fatalf("successor(%q)=%q want %q", id, got, want)
		}
	}
}
