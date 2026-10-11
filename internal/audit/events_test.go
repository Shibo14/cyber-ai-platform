package audit

import (
	"context"
	"cyber-ai-platform/internal/tenantidentity"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const eventTenant = "a0b1c2d3-e4f5-4678-9abc-def012345678"
const otherTenant = "b0b1c2d3-e4f5-4678-9abc-def012345678"

type privacyFunc func(context.Context, string, string) (string, error)

func (f privacyFunc) Reference(c context.Context, k, v string) (string, error) { return f(c, k, v) }

type taxonomyFunc func(context.Context, Input) error

func (f taxonomyFunc) Validate(c context.Context, i Input) error { return f(c, i) }

type writerFunc func(context.Context, Event) error

func (f writerFunc) Write(c context.Context, e Event) error { return f(c, e) }
func fixtureBuilder(t *testing.T) *Builder {
	t.Helper()
	b, err := NewBuilder(privacyFunc(func(_ context.Context, k, v string) (string, error) {
		// Explicit fixture allowlist, not a production PII policy.
		if v == "opaque-1" {
			return v, nil
		}
		return "", errors.New("private rejected input")
	}), taxonomyFunc(func(_ context.Context, i Input) error {
		if i.Kind != "fixture" {
			return ErrInvalidEvent
		}
		return nil
	}), func() time.Time { return time.Unix(10, 0) })
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fixtureInput() Input {
	return Input{Attribution: Attribution{Tenant: eventTenant, Actor: "opaque-1", Subject: "opaque-1", Action: "opaque-1", Resource: "opaque-1", Correlation: "opaque-1"}, Kind: "fixture", Result: Pending}
}

func TestZeroValueAuditDependenciesFailClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Builder{}).Build(ctx, fixtureInput()); err != ErrInvalidEvent {
		t.Fatal(err)
	}
	if err := (&Recorder{}).Record(ctx, fixtureInput()); err != ErrUnavailable {
		t.Fatal(err)
	}
	if records, err := (&ReadService{}).Read(ctx, Query{Tenant: tenantidentity.TenantID(eventTenant), Limit: 1}); err != ErrUnavailable || records != nil {
		t.Fatal(err)
	}
}
func TestEventBuilderPrivacyAndValidation(t *testing.T) {
	b := fixtureBuilder(t)
	e, err := b.Build(context.Background(), fixtureInput())
	if err != nil || e.Data().Timestamp.IsZero() {
		t.Fatal(err)
	}
	for _, secret := range []string{"person@example.test", "Bearer token", "credential", "-----BEGIN PRIVATE KEY-----", "plaintext-DEK", "raw sample body", "raw SQL error"} {
		for _, field := range []string{"actor", "subject", "action", "resource", "correlation"} {
			t.Run(field+"/"+secret, func(t *testing.T) {
				in := fixtureInput()
				switch field {
				case "actor":
					in.Actor = secret
				case "subject":
					in.Subject = secret
				case "action":
					in.Action = secret
				case "resource":
					in.Resource = secret
				case "correlation":
					in.Correlation = secret
				}
				got, err := b.Build(context.Background(), in)
				if err != ErrInvalidEvent || got.valid || strings.Contains(fmt.Sprint(err), secret) {
					t.Fatal("sensitive event admitted")
				}
			})
		}
	}
	for _, mutate := range []func(*Input){func(i *Input) { i.Kind = "unknown" }, func(i *Input) { i.Result = "allowed" }, func(i *Input) { i.Tenant = "invalid" }} {
		in := fixtureInput()
		mutate(&in)
		if _, err := b.Build(context.Background(), in); err == nil {
			t.Fatal("invalid event admitted")
		}
	}
	// Returned data cannot modify an already built event.
	d := e.Data()
	d.Actor = "person@example.test"
	if e.Data().Actor != "opaque-1" {
		t.Fatal("mutable event")
	}
}
func TestRecorderPersistThenFailureAndRecursion(t *testing.T) {
	var saved Event
	r, _ := NewRecorder(fixtureBuilder(t), writerFunc(func(_ context.Context, e Event) error { saved = e; return errors.New("credential=private") }))
	i := fixtureInput()
	i.Result = Committed
	if err := r.Record(context.Background(), i); err != ErrDeliveryUnknown {
		t.Fatal(err)
	}
	if saved.Data().Result != Committed {
		t.Fatal("committed effect misrepresented as rollback")
	}
	i.Result = Pending
	if r.Record(context.Background(), i) != ErrDeliveryUnknown || saved.Data().Result != Pending {
		t.Fatal("false success")
	}
	var nested error
	r, _ = NewRecorder(fixtureBuilder(t), writerFunc(func(ctx context.Context, e Event) error { nested = r.Record(ctx, i); return nil }))
	if r.Record(context.Background(), i) != nil || nested != ErrRecursion {
		t.Fatal("recursive audit was not rejected")
	}
}

type scopeFunc func(context.Context) (Scope, error)

func (f scopeFunc) Resolve(c context.Context) (Scope, error) { return f(c) }

type accessFunc func(context.Context, Scope) (bool, error)

func (f accessFunc) AllowRead(c context.Context, s Scope) (bool, error) { return f(c, s) }

type readerFunc func(context.Context, Scope, int) ([]Record, error)

func (f readerFunc) Read(c context.Context, s Scope, n int) ([]Record, error) { return f(c, s, n) }

type integrityFunc func(context.Context, Scope, []Record) error

func (f integrityFunc) Verify(c context.Context, s Scope, r []Record) error { return f(c, s, r) }
func TestReadAccessIntegrityAndExpiry(t *testing.T) {
	for _, mode := range []string{"valid", "cross-tenant request", "cross-tenant response", "role denied", "integrity failure", "expired during read", "changed principal", "storage failure", "zero event", "oversized response", "missing identity"} {
		t.Run(mode, func(t *testing.T) {
			read := false
			scope := Scope{tenantidentity.TenantID(eventTenant), "reader"}
			resolver := scopeFunc(func(context.Context) (Scope, error) {
				if mode == "missing identity" || read && mode == "expired during read" {
					return Scope{}, ErrAccess
				}
				if read && mode == "changed principal" {
					return Scope{scope.Tenant, "other"}, nil
				}
				return scope, nil
			})
			e, _ := fixtureBuilder(t).Build(context.Background(), fixtureInput())
			reader := readerFunc(func(context.Context, Scope, int) ([]Record, error) {
				read = true
				if mode == "storage failure" {
					return nil, errors.New("private")
				}
				if mode == "cross-tenant response" {
					i := fixtureInput()
					i.Tenant = otherTenant
					e, _ = fixtureBuilder(t).Build(context.Background(), i)
				}
				if mode == "zero event" {
					e = Event{}
				}
				if mode == "oversized response" {
					return []Record{{Event: e}, {Event: e}}, nil
				}
				return []Record{{Event: e}}, nil
			})
			s, _ := NewReadService(resolver, accessFunc(func(context.Context, Scope) (bool, error) { return mode != "role denied", nil }), reader, integrityFunc(func(context.Context, Scope, []Record) error {
				if mode == "integrity failure" {
					return errors.New("private evidence")
				}
				return nil
			}), 2)
			q := Query{scope.Tenant, 1}
			if mode == "cross-tenant request" {
				q.Tenant = tenantidentity.TenantID(otherTenant)
			}
			out, err := s.Read(context.Background(), q)
			if mode == "valid" {
				if err != nil || len(out) != 1 {
					t.Fatal(err)
				}
			} else if err == nil || len(out) != 0 {
				t.Fatal("unauthorized release")
			}
			if (mode == "cross-tenant request" || mode == "role denied" || mode == "missing identity") && read {
				t.Fatal("storage reached before access check")
			}
		})
	}
}
