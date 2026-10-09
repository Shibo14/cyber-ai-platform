package workeridentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"cyber-ai-platform/internal/authorization"
)

type Bridge struct{ config Config }

func New(config Config) (*Bridge, error) {
	if config.Source == nil || config.Verifier == nil || config.Mapper == nil || config.Audit == nil ||
		config.HandshakeTimeout <= 0 || (config.MinTLSVersion != tls.VersionTLS12 && config.MinTLSVersion != tls.VersionTLS13) {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Bridge{config: config}, nil
}

// Session has no public constructor or certificate/state import. It proves a
// peer completed a handshake with this bridge, not merely that a PEM parsed.
// It represents the remote worker, NEVER the Redis server or a consumer name.
type Session struct {
	bridge   *Bridge
	conn     *tls.Conn
	peer     [][]byte
	identity Identity
	actor    authorization.ActorPrincipal
	closed   atomic.Bool
}

func (b *Bridge) emit(err error) error {
	// A nil error means verification reached the final guard, not that
	// authentication succeeded. Audit can block or persist before returning
	// an error; neither case may leave a false success record behind.
	outcome, class := "pending", "none"
	if err != nil {
		outcome = "denied"
		class = Classify(err).Error()
	}
	if b.config.Audit.Emit(map[string]any{"event": "worker_identity", "outcome": outcome, "failure_class": class}) != nil {
		return ErrAudit
	}
	return Classify(err)
}

func (b *Bridge) material(ctx context.Context) (Material, Identity, error) {
	if ctx.Err() != nil {
		return Material{}, Identity{}, ErrDependency
	}
	m, err := b.config.Source.Current(ctx)
	if err != nil || ctx.Err() != nil || m.SVID.PrivateKey == nil || len(m.SVID.Certificate) == 0 || len(m.Bundles) == 0 {
		return Material{}, Identity{}, ErrDependency
	}
	id, err := b.config.Verifier.Verify(ctx, m.SVID.Certificate, m.Bundles, b.config.Now(), x509.ExtKeyUsageServerAuth)
	if err != nil {
		return Material{}, Identity{}, Classify(err)
	}
	signer, ok := m.SVID.PrivateKey.(crypto.Signer)
	if !ok {
		return Material{}, Identity{}, ErrDependency
	}
	leaf, err := x509.ParseCertificate(m.SVID.Certificate[0])
	if err != nil {
		return Material{}, Identity{}, ErrDependency
	}
	certKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return Material{}, Identity{}, ErrDependency
	}
	sourceKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(certKey, sourceKey) {
		return Material{}, Identity{}, ErrDependency
	}
	return m, id, nil
}

func (b *Bridge) verify(ctx context.Context, peer [][]byte, m Material) (Identity, authorization.ActorPrincipal, error) {
	id, err := b.config.Verifier.Verify(ctx, peer, m.Bundles, b.config.Now(), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return Identity{}, "", Classify(err)
	}
	actor, err := b.config.Mapper.Actor(ctx, id)
	if err != nil {
		return Identity{}, "", Classify(err)
	}
	if strings.TrimSpace(string(actor)) == "" {
		return Identity{}, "", ErrDenied
	}
	if b.config.Status != nil {
		active, err := b.config.Status.Active(ctx, id)
		if err != nil {
			return Identity{}, "", ErrDependency
		}
		if !active {
			return Identity{}, "", ErrDenied
		}
	}
	// Dependencies may be slow. Never emit a context after validity elapsed.
	now := b.config.Now()
	if ctx.Err() != nil {
		return Identity{}, "", ErrDependency
	}
	if !id.validAt(now) {
		return Identity{}, "", ErrDenied
	}
	return id, actor, nil
}

// Audit is also a blocking dependency. Emit only a neutral pending event before
// the final validity check. Do not write a success event after that check:
// another blocking write would reopen the expiry window. The returned result
// determines authentication success. A failed final check may be audited as
// denied, but can never return success, even if that denial write fails.
func (b *Bridge) finish(ctx context.Context, err error, local, peer Identity) error {
	if err = b.emit(err); err != nil {
		return err
	}
	now := b.config.Now()
	if ctx.Err() != nil {
		return b.emit(ErrDependency)
	}
	if !local.validAt(now) || !peer.validAt(now) {
		return b.emit(ErrDenied)
	}
	return nil
}

// Accept owns raw on entry and closes it on failure. It is an inbound worker
// transport adapter, not an HTTP/Redis deployment decision. Callers must use
// Session.WorkerContext for each operation and Session.Close on disconnect.
// Full handshakes only; production resumption/invalidation remains undecided.
func (b *Bridge) Accept(ctx context.Context, raw net.Conn) (*Session, error) {
	if b == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, ErrConfiguration
	}
	if raw == nil {
		return nil, b.emit(ErrDenied)
	}
	ctx, cancel := context.WithTimeout(ctx, b.config.HandshakeTimeout)
	defer cancel()
	m, _, err := b.material(ctx)
	if err != nil {
		_ = raw.Close()
		return nil, b.emit(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{m.SVID}, ClientAuth: tls.RequireAnyClientCert,
		MinVersion: b.config.MinTLSVersion, SessionTicketsDisabled: true, Time: b.config.Now}
	var verificationErr error
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		peer := make([][]byte, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			peer[i] = cert.Raw
		}
		_, _, verificationErr = b.verify(ctx, peer, m)
		return verificationErr
	}
	conn := tls.Server(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if verificationErr != nil {
			return nil, b.emit(verificationErr)
		}
		if ctx.Err() != nil {
			return nil, b.emit(ErrDependency)
		}
		return nil, b.emit(ErrDenied)
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.DidResume {
		_ = raw.Close()
		return nil, b.emit(ErrDenied)
	}
	peer := make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		peer[i] = append([]byte(nil), cert.Raw...)
	}
	// Refresh after handshake to prevent reuse of a failed/stale source snapshot.
	m, local, err := b.material(ctx)
	if err != nil {
		_ = raw.Close()
		return nil, b.emit(err)
	}
	id, actor, err := b.verify(ctx, peer, m)
	if err = b.finish(ctx, err, local, id); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &Session{bridge: b, conn: conn, peer: peer, identity: id, actor: actor}, nil
}

func (s *Session) check(ctx context.Context) error {
	if s == nil || s.bridge == nil || s.conn == nil || s.closed.Load() {
		return ErrDenied
	}
	m, local, err := s.bridge.material(ctx)
	var id Identity
	if err == nil {
		var actor authorization.ActorPrincipal
		id, actor, err = s.bridge.verify(ctx, s.peer, m)
		// Trust paths may change on refresh; their fresh validity bounds are
		// checked independently of the stable peer certificate/actor identity.
		if err == nil && (id.ID != s.identity.ID || id.TrustDomain != s.identity.TrustDomain ||
			id.NotBefore != s.identity.NotBefore || id.NotAfter != s.identity.NotAfter || actor != s.actor) {
			err = ErrDenied
		}
	}
	if err = s.bridge.finish(ctx, err, local, id); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrDenied
	}
	return nil
}

func (s *Session) WorkerContext(ctx context.Context) (context.Context, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return authorization.WithVerifiedWorkerCheck(ctx, s.actor, s.check), nil
}

// Conn is the authenticated application transport. Closing must use Close so
// contexts are invalidated locally. It never exports TLS credential state.
func (s *Session) Conn() net.Conn {
	if s == nil {
		return nil
	}
	return s
}
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.conn.Read(p)
	if err != nil {
		s.closed.Store(true)
		if err != io.EOF {
			err = ErrDependency
		}
	}
	return n, err
}
func (s *Session) Write(p []byte) (int, error) {
	n, err := s.conn.Write(p)
	if err != nil {
		s.closed.Store(true)
		err = ErrDependency
	}
	return n, err
}
func (s *Session) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *Session) SetDeadline(t time.Time) error      { return Classify(s.conn.SetDeadline(t)) }
func (s *Session) SetReadDeadline(t time.Time) error  { return Classify(s.conn.SetReadDeadline(t)) }
func (s *Session) SetWriteDeadline(t time.Time) error { return Classify(s.conn.SetWriteDeadline(t)) }
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return ErrDenied
	}
	s.closed.Store(true)
	if s.conn.Close() != nil {
		return ErrDependency
	}
	return nil
}
