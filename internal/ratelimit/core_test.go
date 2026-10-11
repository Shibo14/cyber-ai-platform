package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/tenantidentity"
)

type policyFunc func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error)

func (f policyFunc) Quote(c context.Context, e authorization.Execution, s authorization.AdmissionStage) (Quote, error) {
	return f(c, e, s)
}

type backendFunc func(context.Context, Debit) (Receipt, error)

func (f backendFunc) TryDebit(c context.Context, d Debit) (Receipt, error) { return f(c, d) }

type privacy struct{}

func (privacy) Reference(_ context.Context, k, v string) (string, error) {
	return "fixture-reference", nil
}

type taxonomy struct{}

func (taxonomy) Validate(_ context.Context, i audit.Input) error {
	if i.Kind != "cost_admission" && i.Kind != "cost_debit" {
		return audit.ErrInvalidEvent
	}
	return nil
}

type writerFunc func(context.Context, audit.Event) error

func (f writerFunc) Write(c context.Context, e audit.Event) error { return f(c, e) }
func recorder(t *testing.T, w writerFunc) *audit.Recorder {
	t.Helper()
	b, err := audit.NewBuilder(privacy{}, taxonomy{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := audit.NewRecorder(b, w)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Test-only atomic ledger. Not a production accounting backend/schema/policy.
type ledger struct {
	mu   sync.Mutex
	used map[Key]int64
	seen map[attemptKey]Debit
}
type attemptKey struct {
	tenant tenantidentity.TenantID
	id     string
}

func newLedger() *ledger { return &ledger{used: make(map[Key]int64), seen: make(map[attemptKey]Debit)} }
func (l *ledger) TryDebit(_ context.Context, d Debit) (Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Receipt{Debit: d}
	k := attemptKey{d.Key.Tenant, d.Attempt}
	if old, ok := l.seen[k]; ok {
		if old != d {
			return r, ErrInvalid
		}
		r.Outcome = Duplicate
		return r, nil
	}
	if !CanDebit(l.used[d.Key], d.Cost, d.Limit) {
		return r, nil
	}
	l.used[d.Key] += d.Cost
	l.seen[k] = d
	r.Outcome = Admitted
	return r, nil
}
func execFixture() (context.Context, authorization.Execution) {
	e := authorization.Execution{TenantID: "a0b1c2d3-e4f5-4678-9abc-def012345678", Actor: "api", Subject: "subject", Operation: authorization.Operation{Action: "work", ResourceID: "resource", InputFingerprint: "fingerprint"}, CorrelationID: "correlation"}
	c := authorization.WithVerifiedActor(tenantidentity.WithAuthenticatedIdentity(context.Background(), tenantidentity.Identity{TenantID: e.TenantID, PrincipalID: string(e.Subject)}), e.Actor)
	return c, e
}
func quote() Quote {
	return Quote{Bucket: "bucket", Epoch: "epoch", Version: "version", Attempt: "attempt", Cost: 1, Limit: 5}
}
func TestAtomicConcurrentAdmission(t *testing.T) {
	ctx, e := execFixture()
	l := newLedger()
	var serial atomic.Int64
	c, _ := New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
		q := quote()
		q.Attempt = fmt.Sprint(serial.Add(1))
		return q, nil
	}), l, recorder(t, func(context.Context, audit.Event) error { return nil }))
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Admit(ctx, e, authorization.ExecutionStage) == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 5 || l.used[Key{e.TenantID, "bucket", "epoch"}] != 5 {
		t.Fatal("budget overspent")
	}
}

func TestConcurrentDuplicateAndUncertainDebit(t *testing.T) {
	ctx, e := execFixture()
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint("uncertain=", uncertain), func(t *testing.T) {
			l := newLedger()
			backend := backendFunc(func(c context.Context, d Debit) (Receipt, error) {
				r, err := l.TryDebit(c, d)
				if uncertain && r.Outcome == Admitted {
					return Receipt{}, errors.New("backend timed out after debit")
				}
				return r, err
			})
			core, err := New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
				return quote(), nil
			}), backend, recorder(t, func(context.Context, audit.Event) error { return nil }))
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var allowed atomic.Int64
			for i := 0; i < 40; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if core.Admit(ctx, e, authorization.ExecutionStage) == nil {
						allowed.Add(1)
					}
				}()
			}
			wg.Wait()
			want := int64(1)
			if uncertain {
				want = 0
			}
			if allowed.Load() != want || l.used[Key{e.TenantID, "bucket", "epoch"}] != 1 {
				t.Fatal("duplicate or uncertain debit reused")
			}
		})
	}
}
func TestDuplicateAndAlteredRetryNeverGrantAgain(t *testing.T) {
	ctx, e := execFixture()
	l := newLedger()
	q := quote()
	c, _ := New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
		return q, nil
	}), l, recorder(t, func(context.Context, audit.Event) error { return nil }))
	if c.Admit(ctx, e, authorization.ExecutionStage) != nil {
		t.Fatal("initial debit failed")
	}
	if c.Admit(ctx, e, authorization.ExecutionStage) != ErrReplay {
		t.Fatal("duplicate granted")
	}
	q.Bucket = "other"
	if c.Admit(ctx, e, authorization.ExecutionStage) == nil {
		t.Fatal("attempt rebound")
	}
	if len(l.used) != 1 || l.used[Key{e.TenantID, "bucket", "epoch"}] != 1 {
		t.Fatal("duplicate charged again")
	}
}
func TestInvalidCostsAndBackendFailures(t *testing.T) {
	for _, mode := range []string{"negative", "zero", "over limit", "negative limit", "empty policy version", "missing attempt", "policy error", "backend error", "receipt tamper", "unknown outcome", "cancel during audit", "audit failure", "persist then error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, e := execFixture()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			q := quote()
			calls := 0
			switch mode {
			case "negative":
				q.Cost = -1
			case "zero":
				q.Cost = 0
			case "over limit":
				q.Cost = math.MaxInt64
			case "negative limit":
				q.Limit = -1
			case "empty policy version":
				q.Version = ""
			case "missing attempt":
				q.Attempt = ""
			}
			c, _ := New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
				if mode == "policy error" {
					return q, errors.New("credential private")
				}
				return q, nil
			}), backendFunc(func(_ context.Context, d Debit) (Receipt, error) {
				calls++
				r := Receipt{d, Admitted}
				if mode == "backend error" {
					return r, errors.New("secret backend")
				}
				if mode == "receipt tamper" {
					r.Debit.Key.Tenant = "other"
				}
				if mode == "unknown outcome" {
					r.Outcome = 255
				}
				return r, nil
			}), recorder(t, func(_ context.Context, e audit.Event) error {
				if mode == "cancel during audit" {
					cancel()
				}
				if mode == "audit failure" || mode == "persist then error" {
					if e.Data().Result == audit.Succeeded {
						t.Fatal("false operation success")
					}
					return errors.New("private writer")
				}
				return nil
			}))
			err := c.Admit(ctx, e, authorization.ExecutionStage)
			if err == nil || strings.Contains(fmt.Sprint(err), "private") {
				t.Fatal("not fail closed")
			}
			if mode != "backend error" && mode != "receipt tamper" && mode != "unknown outcome" && calls != 0 {
				t.Fatal("debit before validation")
			}
		})
	}
	if CanDebit(math.MaxInt64, 1, math.MaxInt64) || CanDebit(math.MaxInt64-1, 2, math.MaxInt64) || !CanDebit(math.MaxInt64-1, 1, math.MaxInt64) {
		t.Fatal("overflow")
	}
	if _, err := New(nil, newLedger(), recorder(t, func(context.Context, audit.Event) error { return nil })); err == nil {
		t.Fatal("missing policy")
	}
	if _, err := New(policyFunc(nil), nil, nil); err == nil {
		t.Fatal("missing backend")
	}
}
func TestTenantActorSpoofAndKeyCollision(t *testing.T) {
	ctx, e := execFixture()
	calls := 0
	c, _ := New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
		calls++
		return quote(), nil
	}), newLedger(), recorder(t, func(context.Context, audit.Event) error { return nil }))
	for _, field := range []string{"tenant", "actor", "subject", "missing identity"} {
		t.Run(field, func(t *testing.T) {
			bad := e
			cx := ctx
			switch field {
			case "tenant":
				bad.TenantID = "b0b1c2d3-e4f5-4678-9abc-def012345678"
			case "actor":
				bad.Actor = "worker"
			case "subject":
				bad.Subject = "other"
			case "missing identity":
				cx = context.Background()
			}
			if c.Admit(cx, bad, authorization.ExecutionStage) == nil {
				t.Fatal("spoof admitted")
			}
		})
	}
	if calls != 0 {
		t.Fatal("policy reached for forged attribution")
	}
	if (Key{e.TenantID, "a:b", "c"}).Encode() == (Key{e.TenantID, "a", "b:c"}).Encode() {
		t.Fatal("key collision")
	}
	l := newLedger()
	d := Debit{Key: Key{e.TenantID, "b", "e"}, Attempt: "same", Cost: 1, Limit: 1}
	if r, _ := l.TryDebit(ctx, d); r.Outcome != Admitted {
		t.Fatal("tenant A")
	}
	d.Key.Tenant = "b0b1c2d3-e4f5-4678-9abc-def012345678"
	if r, _ := l.TryDebit(ctx, d); r.Outcome != Admitted {
		t.Fatal("tenant A depleted B")
	}
}
func TestAuditLimiterRecursionAndPostDebitFailure(t *testing.T) {
	ctx, e := execFixture()
	l := newLedger()
	var c *Core
	var nested error
	r := recorder(t, func(cx context.Context, event audit.Event) error {
		nested = c.Admit(cx, e, authorization.ExecutionStage)
		return nil
	})
	c, _ = New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
		return quote(), nil
	}), l, r)
	if err := c.Admit(ctx, e, authorization.ExecutionStage); err != nil || nested != ErrDenied {
		t.Fatal(err, nested)
	}
	// Failure after a confirmed debit is unconfirmed delivery, not a refund or
	// permission to execute. A subsequent identical request cannot spend twice.
	l = newLedger()
	var saved []audit.Data
	r = recorder(t, func(_ context.Context, event audit.Event) error {
		d := event.Data()
		saved = append(saved, d)
		if d.Kind == "cost_debit" {
			return errors.New("credential")
		}
		return nil
	})
	c, _ = New(policyFunc(func(context.Context, authorization.Execution, authorization.AdmissionStage) (Quote, error) {
		return quote(), nil
	}), l, r)
	if c.Admit(ctx, e, authorization.ExecutionStage) != ErrUnavailable {
		t.Fatal("false grant")
	}
	if len(saved) != 2 || saved[1].Kind != "cost_debit" || saved[1].Result != audit.Committed {
		t.Fatal("debit result lost")
	}
	if c.Admit(ctx, e, authorization.ExecutionStage) != ErrReplay || l.used[Key{e.TenantID, "bucket", "epoch"}] != 1 {
		t.Fatal("retry re-admitted")
	}
}
