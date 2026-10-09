package workeridentity

// Test PKI, identity paths, mappings and timing are disposable fixtures, not
// production issuer, algorithm, namespace, topology or lifecycle decisions.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"cyber-ai-platform/internal/audit"
	"cyber-ai-platform/internal/authorization"
)

type sourceDouble struct {
	material  Material
	err       error
	onCurrent func()
}

func (s *sourceDouble) Current(context.Context) (Material, error) {
	if s.onCurrent != nil {
		s.onCurrent()
	}
	return s.material, s.err
}

type mapperDouble func(context.Context, Identity) (authorization.ActorPrincipal, error)

func (f mapperDouble) Actor(c context.Context, i Identity) (authorization.ActorPrincipal, error) {
	return f(c, i)
}

type statusDouble func(context.Context, Identity) (bool, error)

func (f statusDouble) Active(c context.Context, i Identity) (bool, error) { return f(c, i) }

type fixture struct {
	now    time.Time
	ca     *x509.Certificate
	key    ed25519.PrivateKey
	roots  *x509.CertPool
	source *sourceDouble
	config Config
	log    bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Now().UTC().Truncate(time.Second)}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: f.now.Add(-24 * time.Hour), NotAfter: f.now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	f.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.ca)
	v, err := NewX509Verifier([]string{"fixture.test"}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.source = &sourceDouble{material: Material{SVID: f.cert(t, "spiffe://fixture.test/service", nil), Bundles: map[string]*x509.CertPool{"fixture.test": f.roots}}}
	f.config = Config{Source: f.source, Verifier: v, Mapper: mapperDouble(func(_ context.Context, i Identity) (authorization.ActorPrincipal, error) {
		switch i.ID {
		case "spiffe://fixture.test/worker-a":
			return "worker-a", nil
		case "spiffe://fixture.test/worker-b":
			return "worker-b", nil
		}
		return "", nil
	}), Audit: audit.New(&f.log, "event", "outcome", "failure_class"), Now: func() time.Time { return f.now }, HandshakeTimeout: 3 * time.Second, MinTLSVersion: tls.VersionTLS13}
	return f
}

func (f *fixture) cert(t *testing.T, id string, mutate func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "fixture leaf"}, URIs: []*url.URL{u}, DNSNames: []string{"localhost"}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if mutate != nil {
		mutate(c)
	}
	der, err := x509.CreateCertificate(rand.Reader, c, f.ca, pub, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *fixture) connect(t *testing.T, cert tls.Certificate) (*Session, error) {
	t.Helper()
	b, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	type result struct {
		s   *Session
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			ch <- result{err: ErrDependency}
			return
		}
		s, err := b.Accept(context.Background(), raw)
		ch <- result{s, err}
	}()
	raw, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{RootCAs: f.roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: f.config.MinTLSVersion, Time: func() time.Time { return f.now }, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	clientErr := client.HandshakeContext(ctx)
	r := <-ch
	if r.err == nil && clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	t.Cleanup(func() {
		_ = raw.Close()
		if r.s != nil {
			_ = r.s.Close()
		}
	})
	return r.s, r.err
}
