// Package redis implements metadata-only Redis Streams transport. Production
// Redis clients, deployment/topology, transport protection, retention and replay
// policies remain injected decisions. Consumer ownership never grants authority.
package redis

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyber-ai-platform/internal/queue"
)

// Commander adapters normalize replies to RESP2 primitives: string, int64,
// []any, or nil. They must honor ctx and must not log command bodies or raw SDK
// errors. No production client, credentials, or connection policy is selected.
type Commander interface {
	Do(context.Context, ...any) (any, error)
}

// DLQFields selects the transport field names, not a final replay format.
// Dead letters contain only the source ID and bounded sanitized failure data.
type DLQFields struct{ SourceID, Class, Reason, Attempts string }

type Config struct {
	Commander Commander
	Stream    string
	Group     string
	Consumer  string
	DLQ       string
	Schema    *queue.Schema
	DLQFields DLQFields
}

type Adapter struct {
	config       Config
	pendingMu    sync.Mutex
	pendingStart string
}

var _ queue.Broker = (*Adapter)(nil)

func New(config Config) (*Adapter, error) {
	if config.Commander == nil || config.Schema == nil || !name(config.Stream) ||
		!name(config.Group) || !name(config.Consumer) || !name(config.DLQ) || config.Stream == config.DLQ {
		return nil, queue.ErrConfiguration
	}
	seen := map[string]bool{}
	for _, field := range []string{config.DLQFields.SourceID, config.DLQFields.Class, config.DLQFields.Reason, config.DLQFields.Attempts} {
		if !fieldName(field) || seen[field] {
			return nil, queue.ErrConfiguration
		}
		seen[field] = true
	}
	return &Adapter{config: config}, nil
}

func name(value string) bool {
	return strings.TrimSpace(value) != "" && !strings.ContainsAny(value, "\x00\r\n")
}

func fieldName(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func safeError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, queue.ErrPermission):
		return queue.ErrPermission
	case errors.Is(err, queue.ErrUnavailable):
		return queue.ErrUnavailable
	default:
		return queue.ErrDependency
	}
}

func (a *Adapter) Key(id string) (queue.DeliveryKey, error) {
	if !validID(id) {
		return queue.DeliveryKey{}, queue.ErrMalformed
	}
	return queue.DeliveryKey{Stream: a.config.Stream, Group: a.config.Group, ID: id}, nil
}

// CreateGroup is explicit; startup never silently creates or resets a group.
// The caller chooses the initial ID and whether to create a missing stream.
// An existing group is reported as a safe dependency error, not hidden by parsing
// a raw server error string.
func (a *Adapter) CreateGroup(ctx context.Context, startID string, makeStream bool) error {
	if startID != "$" && startID != "0" && !validID(startID) {
		return queue.ErrConfiguration
	}
	args := []any{"XGROUP", "CREATE", a.config.Stream, a.config.Group, startID}
	if makeStream {
		args = append(args, "MKSTREAM")
	}
	response, err := a.config.Commander.Do(ctx, args...)
	if err != nil {
		return safeError(err)
	}
	if response != "OK" {
		return queue.ErrProtocol
	}
	return nil
}

func (a *Adapter) Publish(ctx context.Context, fields queue.Fields) (string, error) {
	// Validate even direct adapter calls: arbitrary payloads or retry/authority
	// fields cannot be written by bypassing the queue producer.
	if _, err := a.config.Schema.Decode(fields); err != nil {
		return "", err
	}
	return a.add(ctx, a.config.Stream, fields)
}

func (a *Adapter) add(ctx context.Context, stream string, fields queue.Fields) (string, error) {
	names := make([]string, 0, len(fields))
	for field := range fields {
		names = append(names, field)
	}
	sort.Strings(names)
	args := []any{"XADD", stream, "*"}
	for _, field := range names {
		args = append(args, field, fields[field])
	}
	response, err := a.config.Commander.Do(ctx, args...)
	if err != nil {
		return "", safeError(err)
	}
	id, ok := response.(string)
	if !ok || !validID(id) {
		return "", queue.ErrProtocol
	}
	return id, nil
}

func (a *Adapter) Read(ctx context.Context, count int64) ([]queue.Delivery, error) {
	return a.read(ctx, count, ">")
}

// ReadPending reads this configured consumer's existing PEL without claiming
// another consumer's entries. Recovery timing/ownership policy stays external.
func (a *Adapter) ReadPending(ctx context.Context, count int64) ([]queue.Delivery, error) {
	return a.read(ctx, count, "0")
}

func (a *Adapter) read(ctx context.Context, count int64, start string) ([]queue.Delivery, error) {
	if count <= 0 {
		return nil, queue.ErrConfiguration
	}
	response, err := a.config.Commander.Do(ctx, "XREADGROUP", "GROUP", a.config.Group, a.config.Consumer,
		"COUNT", count, "STREAMS", a.config.Stream, start)
	if err != nil {
		return nil, safeError(err)
	}
	entries, ok := parseRead(response, a.config.Stream)
	if !ok || int64(len(entries)) > count {
		return nil, queue.ErrProtocol
	}
	return a.deliveries(entries), nil
}

func (a *Adapter) deliveries(entries []rawEntry) []queue.Delivery {
	result := make([]queue.Delivery, len(entries))
	for i, entry := range entries {
		delivery := queue.Delivery{ID: entry.id, Invalid: true}
		if !entry.malformed {
			fields := make(queue.Fields, len(entry.fields)/2)
			for j := 0; j < len(entry.fields); j += 2 {
				fields[entry.fields[j]] = entry.fields[j+1]
			}
			// Only configured metadata fields survive. Unsupported schema/version
			// remains distinguishable by the core; raw malformed bodies are gone.
			if _, err := a.config.Schema.Decode(fields); err == nil || errors.Is(err, queue.ErrUnsupported) {
				delivery.Fields, delivery.Invalid = fields, false
			}
		}
		result[i] = delivery
	}
	return result
}

func (a *Adapter) Pending(ctx context.Context, count int64) ([]queue.Pending, error) {
	// Page through the PEL instead of repeatedly inspecting the first count
	// entries: a recent first entry must not starve older later entries. Paging
	// is transport observation only, never an authorization or retry counter.
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	start := a.pendingStart
	if start == "" {
		start = "-"
	}
	result, err := a.PendingRange(ctx, start, "+", count)
	if err != nil {
		return nil, err
	}
	if len(result) == 0 && start != "-" {
		result, err = a.PendingRange(ctx, "-", "+", count)
		if err != nil {
			return nil, err
		}
	}
	a.pendingStart = "-"
	if int64(len(result)) == count {
		a.pendingStart = successor(result[len(result)-1].ID)
	}
	return result, nil
}

func successor(id string) string {
	parts := strings.Split(id, "-") // callers use previously validated IDs
	milliseconds, _ := strconv.ParseUint(parts[0], 10, 64)
	sequence, _ := strconv.ParseUint(parts[1], 10, 64)
	if sequence == ^uint64(0) {
		if milliseconds == ^uint64(0) {
			return "-"
		}
		return strconv.FormatUint(milliseconds+1, 10) + "-0"
	}
	return strconv.FormatUint(milliseconds, 10) + "-" + strconv.FormatUint(sequence+1, 10)
}

// PendingRange permits caller-managed pagination without selecting a recovery
// cadence, ownership policy, or minimum idle time.
func (a *Adapter) PendingRange(ctx context.Context, start, end string, count int64) ([]queue.Pending, error) {
	if count <= 0 || (start != "-" && !validID(start)) || (end != "+" && !validID(end)) {
		return nil, queue.ErrConfiguration
	}
	response, err := a.config.Commander.Do(ctx, "XPENDING", a.config.Stream, a.config.Group, start, end, count)
	if err != nil {
		return nil, safeError(err)
	}
	items, ok := response.([]any)
	if !ok || int64(len(items)) > count {
		return nil, queue.ErrProtocol
	}
	result := make([]queue.Pending, len(items))
	seen := map[string]bool{}
	for i, item := range items {
		fields, ok := item.([]any)
		if !ok || len(fields) != 4 {
			return nil, queue.ErrProtocol
		}
		id, idOK := fields[0].(string)
		consumer, consumerOK := fields[1].(string)
		idle, idleOK := fields[2].(int64)
		deliveries, deliveriesOK := fields[3].(int64)
		if !idOK || !validID(id) || seen[id] || !consumerOK || !name(consumer) || !idleOK || idle < 0 ||
			idle > int64((1<<63-1)/time.Millisecond) || !deliveriesOK || deliveries < 0 {
			return nil, queue.ErrProtocol
		}
		seen[id] = true
		result[i] = queue.Pending{ID: id, Consumer: consumer, Idle: time.Duration(idle) * time.Millisecond, Deliveries: uint64(deliveries)}
	}
	return result, nil
}

func (a *Adapter) Claim(ctx context.Context, ids []string, minIdle time.Duration) ([]queue.Delivery, error) {
	if len(ids) == 0 || minIdle < 0 || minIdle%time.Millisecond != 0 {
		return nil, queue.ErrConfiguration
	}
	args := []any{"XCLAIM", a.config.Stream, a.config.Group, a.config.Consumer, minIdle.Milliseconds()}
	seen := map[string]bool{}
	for _, id := range ids {
		if !validID(id) || seen[id] {
			return nil, queue.ErrMalformed
		}
		seen[id] = true
		args = append(args, id)
	}
	response, err := a.config.Commander.Do(ctx, args...)
	if err != nil {
		return nil, safeError(err)
	}
	entries, ok := parseEntries(response)
	if !ok || len(entries) > len(ids) {
		return nil, queue.ErrProtocol
	}
	for _, entry := range entries {
		if !seen[entry.id] {
			return nil, queue.ErrProtocol
		}
	}
	return a.deliveries(entries), nil
}

func (a *Adapter) Ack(ctx context.Context, id string) error {
	if !validID(id) {
		return queue.ErrMalformed
	}
	response, err := a.config.Commander.Do(ctx, "XACK", a.config.Stream, a.config.Group, id)
	if err != nil {
		return safeError(err)
	}
	acked, ok := response.(int64)
	if !ok || (acked != 0 && acked != 1) {
		return queue.ErrProtocol
	}
	// Zero means already not pending. Business completion/authorization is the
	// core's responsibility; this is transport idempotence, not exactly-once.
	return nil
}

func (a *Adapter) WriteDLQ(ctx context.Context, letter queue.DeadLetter) (string, error) {
	if !validID(letter.SourceID) || !(queue.Classification{Class: letter.Class, Reason: letter.Reason}).Valid() {
		return "", queue.ErrMalformed
	}
	fields := a.config.DLQFields
	// This method never acknowledges the source. DLQ XADD must be confirmed
	// before the core attempts XACK; no MULTI/runtime-error rollback assumption.
	return a.add(ctx, a.config.DLQ, queue.Fields{fields.SourceID: letter.SourceID, fields.Class: string(letter.Class),
		fields.Reason: string(letter.Reason), fields.Attempts: strconv.FormatUint(uint64(letter.Attempts), 10)})
}
