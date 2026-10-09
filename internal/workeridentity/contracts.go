// Package workeridentity authenticates worker transports. It grants no tenant,
// subject, approval or business authority. Issuer and deployment remain injected.
package workeridentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
)

// Identity is verified certificate metadata, not a tenant selector or grant.
type Identity struct {
	ID, TrustDomain     string
	NotBefore, NotAfter time.Time
	// Intersection of validity periods in a successfully verified chain,
	// including the leaf and trust anchor. Leaf lifetime above stays distinct.
	ChainNotBefore, ChainNotAfter time.Time
}

func (i Identity) validAt(now time.Time) bool {
	return !i.NotBefore.IsZero() && i.NotAfter.After(i.NotBefore) &&
		!i.ChainNotBefore.IsZero() && i.ChainNotAfter.After(i.ChainNotBefore) &&
		!now.Before(i.NotBefore) && now.Before(i.NotAfter) &&
		!now.Before(i.ChainNotBefore) && now.Before(i.ChainNotAfter)
}

// Source returns a CURRENT immutable snapshot on every call, or an error when
// refresh cannot be confirmed. Implementations own key custody, rotation and
// concurrency; they must not silently return stale snapshots on refresh failure.
// Session guards retain peer public certificates. The TLS stack/source may
// retain local key references in memory; the core never persists/serializes them.
// All injected dependencies must honor context cancellation and must never log
// key material, credential-bearing structures or raw dependency errors.
type Source interface {
	Current(context.Context) (Material, error)
}
type Material struct {
	SVID    tls.Certificate
	Bundles map[string]*x509.CertPool
}

// Mapper is trusted server configuration. Unknown/unapproved identities must
// return an empty actor or error; it must not infer tenant authority from IDs.
type Mapper interface {
	Actor(context.Context, Identity) (authorization.ActorPrincipal, error)
}

// Verifier verifies certificate identity and trust, NOT proof of key possession.
// Only Bridge.Accept's completed TLS handshake can create a Session/context.
// Successful results must include leaf and verified-chain validity bounds so
// the bridge can recheck evidence after blocking dependencies, including audit.
type Verifier interface {
	Verify(context.Context, [][]byte, map[string]*x509.CertPool, time.Time, x509.ExtKeyUsage) (Identity, error)
}

// Status is an optional current withdrawal/quarantine policy integration.
// An error or false denies. No revocation protocol, CRL or quarantine action is
// supplied here; absence means no withdrawal mechanism has been implemented.
type Status interface {
	Active(context.Context, Identity) (bool, error)
}

type Config struct {
	Source   Source
	Verifier Verifier
	Mapper   Mapper
	Status   Status
	Audit    *audit.Logger
	Now      func() time.Time
	// Explicit deployment settings: there are no lifetime/handshake defaults.
	HandshakeTimeout time.Duration
	MinTLSVersion    uint16
}
