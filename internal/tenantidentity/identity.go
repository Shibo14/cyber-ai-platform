// Package tenantidentity carries tenant identity from a trusted authentication
// integration to tenant-scoped handlers. It does not implement authentication
// or choose an identity provider.
package tenantidentity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TenantID is a canonical PostgreSQL UUID supplied by trusted authentication
// middleware after it has authenticated the principal and authorized the
// tenant membership.
type TenantID string

// ParseTenantID validates the canonical UUID text used by the database schema.
func ParseTenantID(raw string) (TenantID, error) {
	if len(raw) != 36 || raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return "", errors.New("tenant ID must be a canonical UUID")
	}
	compact := strings.ReplaceAll(raw, "-", "")
	if len(compact) != 32 {
		return "", errors.New("tenant ID must be a canonical UUID")
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return "", fmt.Errorf("tenant ID must be a canonical UUID: %w", err)
	}
	return TenantID(strings.ToLower(raw)), nil
}

// Identity is the verified tenant and opaque principal identifier established
// by an authentication integration. The principal format is identity-provider
// agnostic; no provider or user workflow is selected here.
type Identity struct {
	TenantID    TenantID
	PrincipalID string
}

type identityContextKey struct{}

// WithAuthenticatedIdentity attaches an identity already verified by trusted
// authentication and tenant-membership middleware. Never populate it from an
// unchecked request header or query parameter.
func WithAuthenticatedIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// FromContext returns the identity supplied by trusted authentication middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

// RequireIdentity is a chi-compatible middleware. Routes using it fail closed
// unless the upstream authentication integration populated a verified identity.
func RequireIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := FromContext(r.Context())
		if !ok || identity.TenantID == "" || strings.TrimSpace(identity.PrincipalID) == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := ParseTenantID(string(identity.TenantID)); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
