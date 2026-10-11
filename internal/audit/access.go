package audit

import (
	"context"
	"cyber-ai-platform/internal/tenantidentity"
)

type Scope struct {
	Tenant    tenantidentity.TenantID
	Principal string
}

// Resolve authenticates the caller and derives its authoritative tenant/role
// context. It must reject expired worker evidence and cannot trust query fields.
type ScopeResolver interface {
	Resolve(context.Context) (Scope, error)
}
type AccessPolicy interface {
	AllowRead(context.Context, Scope) (bool, error)
}
type Query struct {
	Tenant tenantidentity.TenantID
	Limit  int
}
type Record struct {
	Event    Event
	Evidence []byte
}

// Reader adapters enforce tenant isolation in storage too. A PostgreSQL adapter
// must use CYB-12 WithTenantTx/RLS; no production backend is selected here.
type Reader interface {
	Read(context.Context, Scope, int) ([]Record, error)
}

// Verify authenticates the complete returned batch and relevant scope/order/
// completeness evidence under an approved integrity scheme. No hash/WORM default.
type Integrity interface {
	Verify(context.Context, Scope, []Record) error
}
type ReadService struct {
	resolver  ScopeResolver
	policy    AccessPolicy
	reader    Reader
	integrity Integrity
	max       int
}

func NewReadService(s ScopeResolver, p AccessPolicy, r Reader, i Integrity, max int) (*ReadService, error) {
	if s == nil || p == nil || r == nil || i == nil || max <= 0 {
		return nil, ErrUnavailable
	}
	return &ReadService{s, p, r, i, max}, nil
}
func (s *ReadService) authorize(ctx context.Context, tenant tenantidentity.TenantID) (Scope, error) {
	scope, err := s.resolver.Resolve(ctx)
	t, parseErr := tenantidentity.ParseTenantID(string(scope.Tenant))
	if err != nil || parseErr != nil || t != scope.Tenant || scope.Tenant != tenant || scope.Principal == "" {
		return Scope{}, ErrAccess
	}
	allowed, err := s.policy.AllowRead(ctx, scope)
	if err != nil || !allowed || ctx.Err() != nil {
		return Scope{}, ErrAccess
	}
	// Access policy can also block; Resolve must perform a current validity check.
	fresh, err := s.resolver.Resolve(ctx)
	if err != nil || fresh != scope || ctx.Err() != nil {
		return Scope{}, ErrAccess
	}
	return scope, nil
}
func (s *ReadService) Read(ctx context.Context, q Query) ([]Event, error) {
	if s == nil || s.resolver == nil || s.policy == nil || s.reader == nil || s.integrity == nil || s.max <= 0 {
		return nil, ErrUnavailable
	}
	if q.Limit <= 0 || q.Limit > s.max {
		return nil, ErrAccess
	}
	scope, err := s.authorize(ctx, q.Tenant)
	if err != nil {
		return nil, err
	}
	records, err := s.reader.Read(ctx, scope, q.Limit)
	if err != nil || len(records) > q.Limit {
		return nil, ErrUnavailable
	}
	// Copy mutable proof data before handing it to another dependency.
	batch := make([]Record, len(records))
	out := make([]Event, len(records))
	for n, r := range records {
		if !r.Event.valid || r.Event.data.Tenant != string(scope.Tenant) {
			return nil, ErrAccess
		}
		batch[n] = Record{r.Event, append([]byte(nil), r.Evidence...)}
		out[n] = r.Event
	}
	if s.integrity.Verify(ctx, scope, batch) != nil {
		return nil, ErrIntegrity
	}
	// Slow storage/integrity checks cannot preserve expired or changed access.
	fresh, err := s.authorize(ctx, q.Tenant)
	if err != nil || fresh != scope {
		return nil, ErrAccess
	}
	return out, nil
}
