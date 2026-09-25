package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	host_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/sys/host"
	key_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/sys/key"
	x509_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/sys/x509"
)

// orderLog records the SEQUENCE of durable writes across both stores. The stratum
// record and the kernel mirror have separate fakes, and the only way to assert
// "stratum first" is to have both append to one shared log.
type orderLog struct {
	mu    sync.Mutex
	steps []string
}

func (o *orderLog) note(step string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.steps = append(o.steps, step)
}

func (o *orderLog) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.steps...)
}

// fakeCertRecord is a stand-in for the LetsEncryptCert record in stratum. It holds
// the one row the real store holds for a hostname set, records every publish, and
// can be made to fail.
type fakeCertRecord struct {
	mu         sync.Mutex
	current    *letsencrypt_pb.LetsEncryptCert
	published  []*letsencrypt_pb.LetsEncryptCert
	publishErr error
	fetchErr   error
	order      *orderLog
}

func (f *fakeCertRecord) Fetch(context.Context) (*letsencrypt_pb.LetsEncryptCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.current, nil
}

func (f *fakeCertRecord) Publish(_ context.Context, rec *letsencrypt_pb.LetsEncryptCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.publishErr != nil {
		return f.publishErr
	}
	f.order.note("stratum")
	f.current = rec
	f.published = append(f.published, rec)
	return nil
}

func (f *fakeCertRecord) writes() []*letsencrypt_pb.LetsEncryptCert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*letsencrypt_pb.LetsEncryptCert(nil), f.published...)
}

// newRecordTestCertManager builds a CertManager wired to a fake stratum and a fake
// kernel, both reporting into one shared write-order log, with the account-store
// hook installed exactly as Run installs it.
func newRecordTestCertManager(hostname string, interval int64) (*CertManager, *fakeCertRecord, *fakeCertData, *orderLog) {
	order := &orderLog{}
	record := &fakeCertRecord{order: order}
	kernel := &fakeCertData{order: order}
	cm := &CertManager{
		cfg: &letsencrypt_pb.Config{
			LetsEncryptEmail:            "admin@example.test",
			HttpListener:                &host_pb.Host{Host: "127.0.0.1", Port: 0},
			RenewalCheckIntervalSeconds: interval,
		},
		hostnames:  []string{hostname},
		storage:    NewStorage(),
		certData:   kernel,
		certRecord: record,
		certSetID:  certSetID([]string{hostname}),
	}
	cm.storage.SetAccountStoreHook(cm.persistAccount)
	return cm, record, kernel, order
}

// ---------------------------------------------------------------------------
// (a) a valid unexpired stratum record on startup skips ACME entirely
// ---------------------------------------------------------------------------

// The whole point of item 4 of the no-durability decision: the certificate is
// durable in stratum, so a cold start — a start whose kernel state is empty,
// which is every start once kernel stops persisting — must serve the stored
// certificate and not open an ACME order. Let's Encrypt allows 5 duplicate
// certificates per week per identifier; a fleet that re-obtained on every boot
// would exhaust that and then serve the fallback cluster-CA cert.
//
// The issuer here FAILS every issuance and reports when it is asked, so an ACME
// attempt cannot pass unnoticed.
func TestValidRecordOnStartupSkipsACME(t *testing.T) {
	issuer := newFailingIssuer()
	installTestIssuer(t, issuer)

	// A hostname this process has never managed, so certmagic's process-global
	// certificate cache cannot answer for it and the certificate must come from the
	// storage tree the record restored. Without that, the test would pass on a
	// cached certificate and prove nothing.
	hostname := fmt.Sprintf("valid-record-%d.example.test", time.Now().UnixNano())

	cm, record, kernel, _ := newRecordTestCertManager(hostname, 1)
	seeded := seedValidRecord(t, cm, record, hostname, 90*24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	// PROOF THAT CERTMAGIC SERVED THE RESTORED CERTIFICATE, not merely that nothing
	// happened: extractAndStore rebuilds the chain from the tls.Certificate
	// certmagic handed it, and tlsCertToProto stamps that chain "le-chain-…" — a
	// prefix the seeded record's "le-seed-…" cannot produce. A kernel write carrying
	// one therefore means certmagic loaded the certificate out of the restored
	// storage tree and cached it. Without this, a certmagic that quietly did nothing
	// at all would pass the no-ACME check below.
	served := waitForChainPrefix(t, kernel, "le-chain-", 15*time.Second)
	if served == nil {
		t.Fatal("certmagic never served the certificate the record restored")
	}

	// The renewal check interval is 1s, so several ticks pass inside this window.
	// Any of them would have driven an obtain if the record had not been believed.
	select {
	case <-issuer.called:
		cancel()
		t.Fatal("ACME was attempted even though stratum held a valid unexpired certificate")
	case <-time.After(3 * time.Second):
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	if got := issuer.attemptCount(); got != 0 {
		t.Errorf("issuer attempts = %d, want 0", got)
	}

	// And the record reached the kernel mirror, which is what the gateway watches.
	mirrored := kernel.writes()
	if len(mirrored) == 0 {
		t.Fatal("the record was never mirrored into kernel")
	}
	if got := mirrored[0].GetTlsCert().GetId(); got != seeded.GetTlsCert().GetId() {
		t.Errorf("mirrored chain id = %q, want %q", got, seeded.GetTlsCert().GetId())
	}
}

// ---------------------------------------------------------------------------
// (b) an expired or absent record triggers ACME
// ---------------------------------------------------------------------------

// An ABSENT record is the first-ever start: nothing durable exists, so ACME is the
// only way to get a certificate.
func TestAbsentRecordTriggersACME(t *testing.T) {
	assertACMEAttempted(t, func(*CertManager, *fakeCertRecord, string) {
		// nothing seeded — stratum holds no row for this hostname set
	})
}

// An EXPIRED record must trigger ACME rather than be served. The certificate here
// is inside certmagic's own renewal window (its whole lifetime is behind it), which
// is the same line recordUsable draws.
func TestExpiredRecordTriggersACME(t *testing.T) {
	assertACMEAttempted(t, func(cm *CertManager, record *fakeCertRecord, hostname string) {
		seedValidRecord(t, cm, record, hostname, -time.Hour)
	})
}

// A record whose read FAILS must also fall through to ACME rather than leave the
// cluster with no certificate at all. Stratum being unreachable costs an ACME order
// at worst; treating it as fatal would cost the cluster its TLS listener.
func TestUnreadableRecordTriggersACME(t *testing.T) {
	assertACMEAttempted(t, func(_ *CertManager, record *fakeCertRecord, _ string) {
		record.fetchErr = errors.New("stratum unavailable")
	})
}

func assertACMEAttempted(t *testing.T, seed func(*CertManager, *fakeCertRecord, string)) {
	t.Helper()
	issuer := newFailingIssuer()
	installTestIssuer(t, issuer)

	hostname := fmt.Sprintf("needs-acme-%d.example.test", time.Now().UnixNano())
	cm, record, _, _ := newRecordTestCertManager(hostname, 1)
	seed(cm, record, hostname)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	select {
	case <-issuer.called:
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("ACME was never attempted, so the cluster would have no certificate")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

// ---------------------------------------------------------------------------
// (c) on obtain, stratum is written before kernel state
// ---------------------------------------------------------------------------

// ORDER MATTERS, so it is asserted and not eyeballed. Kernel holds nothing
// durably; a kernel write that landed while the stratum write failed would leave a
// mirror with no durable copy behind it, and the next start would obtain a fresh
// certificate while the gateway still served the one kernel remembered.
func TestObtainWritesStratumBeforeKernel(t *testing.T) {
	installTestIssuer(t, newSigningIssuer(t))

	hostname := fmt.Sprintf("order-%d.example.test", time.Now().UnixNano())
	// An hour between renewal checks, so nothing here can be the ticker's work.
	cm, record, kernel, order := newRecordTestCertManager(hostname, 3600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	waitForStoredCert(t, kernel, 15*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	steps := order.snapshot()
	if len(steps) < 2 {
		t.Fatalf("expected at least one stratum write and one kernel write, got %v", steps)
	}
	if steps[0] != "stratum" {
		t.Errorf("first durable write was %q, want \"stratum\"", steps[0])
	}
	// Every kernel write must be preceded by a stratum write of its own, not merely
	// the first one. A renewal that reversed the pair on a later pass is the same
	// defect, so the pairing is checked across the whole sequence.
	pendingStratum := 0
	for i, step := range steps {
		switch step {
		case "stratum":
			pendingStratum++
		case "kernel":
			if pendingStratum == 0 {
				t.Fatalf("kernel write at step %d has no stratum write of its own before it: %v", i, steps)
			}
			pendingStratum--
		}
	}

	// And what stratum got is the certificate, with the derived metadata on it.
	published := record.writes()
	var withCert *letsencrypt_pb.LetsEncryptCert
	for _, rec := range published {
		if rec.GetTlsCert() != nil {
			withCert = rec
			break
		}
	}
	if withCert == nil {
		t.Fatal("no published record carried a certificate")
	}
	if withCert.GetCertSetId() != cm.certSetID {
		t.Errorf("published cert_set_id = %q, want %q", withCert.GetCertSetId(), cm.certSetID)
	}
	if withCert.GetExpiresAt() <= withCert.GetIssuedAt() {
		t.Errorf("published issued_at/expires_at = %d/%d, want expires after issued",
			withCert.GetIssuedAt(), withCert.GetExpiresAt())
	}
	if got := withCert.GetHostnames(); len(got) != 1 || got[0] != hostname {
		t.Errorf("published hostnames = %v, want [%s]", got, hostname)
	}
	if withCert.GetCertmagicState() == nil {
		t.Error("published record carries no CertMagic tree, so the ACME account is not durable")
	}
}

// A failed stratum write must NOT be followed by a kernel write. Writing the mirror
// anyway is the silent version of the defect above: the gateway would serve a
// certificate nothing durable knows about.
func TestStratumWriteFailureBlocksKernelWrite(t *testing.T) {
	cm, record, kernel, order := newRecordTestCertManager("api.example.test", 3600)
	record.publishErr = errors.New("eventbus unavailable")

	err := cm.store(context.Background(), &letsencrypt_pb.LetsEncryptCertData{
		CertmagicState: NewStorage().ToProto(),
		Hostnames:      cm.hostnames,
	})
	if err == nil {
		t.Fatal("store returned nil although the stratum write failed")
	}
	if len(kernel.writes()) != 0 {
		t.Errorf("kernel was written %d times after the stratum write failed", len(kernel.writes()))
	}
	if steps := order.snapshot(); len(steps) != 0 {
		t.Errorf("durable writes = %v, want none", steps)
	}
}

// The ACME ACCOUNT has to be durable before issuance finishes, and kernel is no
// longer a place where anything is durable — so the account flush has to reach the
// record too, with no certificate on it yet.
func TestAccountFlushReachesStratum(t *testing.T) {
	cm, record, _, order := newRecordTestCertManager("api.example.test", 3600)
	ctx := context.Background()

	storeCompleteAccount(t, cm, ctx)

	published := record.writes()
	if len(published) != 1 {
		t.Fatalf("expected 1 record write once the account was complete, got %d", len(published))
	}
	if published[0].GetTlsCert() != nil {
		t.Error("the account flush published a certificate it does not have")
	}
	for _, key := range []string{testAccountReg, testAccountKey} {
		if !hasKey(published[0].GetCertmagicState(), key) {
			t.Errorf("published CertMagic tree is missing %s", key)
		}
	}
	if steps := order.snapshot(); len(steps) != 2 || steps[0] != "stratum" || steps[1] != "kernel" {
		t.Errorf("write order = %v, want [stratum kernel]", steps)
	}
}

// ---------------------------------------------------------------------------
// the key
// ---------------------------------------------------------------------------

func TestCertSetIDDependsOnTheSetNotTheOrder(t *testing.T) {
	a := certSetID([]string{"api.example.test", "console.example.test"})
	b := certSetID([]string{"console.example.test", "api.example.test"})
	if a != b {
		t.Errorf("reordering the hostname list changed the key: %q vs %q", a, b)
	}
	c := certSetID([]string{"api.example.test"})
	if a == c {
		t.Error("a different hostname set produced the same key, so a config change would reuse a certificate that does not cover it")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// seedValidRecord puts a certificate for hostname into the fake stratum record, in
// the CertMagic storage layout certmagic itself loads from — so a Run over it takes
// exactly the path a real restored record takes, rather than a shortcut the
// production code does not have.
//
// validFor is the remaining lifetime: a positive duration gives a certificate
// certmagic will serve, a negative one gives an expired certificate it must renew.
func seedValidRecord(t *testing.T, cm *CertManager, record *fakeCertRecord, hostname string, validFor time.Duration) *letsencrypt_pb.LetsEncryptCert {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "letsencrypt seed CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	// NotBefore is placed a full lifetime before NotAfter so the renewal window
	// recordUsable computes is the real one, not a window derived from a
	// zero-length lifetime.
	notAfter := time.Now().Add(validFor)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshaling leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	meta, err := json.Marshal(certmagic.CertificateResource{SANs: []string{hostname}})
	if err != nil {
		t.Fatalf("marshaling certificate metadata: %v", err)
	}

	// The issuer key is the test issuer's, because that is the issuer Run installs
	// and therefore the directory certmagic's loadCertResource looks in.
	const issuerKey = "test-failing-issuer"
	tree := NewStorage()
	ctx := context.Background()
	for key, value := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(issuerKey, hostname):       certPEM,
		certmagic.StorageKeys.SitePrivateKey(issuerKey, hostname): keyPEM,
		certmagic.StorageKeys.SiteMeta(issuerKey, hostname):       meta,
	} {
		if err := tree.Store(ctx, key, value); err != nil {
			t.Fatalf("seeding %s: %v", key, err)
		}
	}

	rec := &letsencrypt_pb.LetsEncryptCert{
		CertSetId:      cm.certSetID,
		TlsCert:        seedChain(certPEM, keyPEM),
		CertmagicState: tree.ToProto(),
		Hostnames:      []string{hostname},
		IssuedAt:       leafTmpl.NotBefore.Unix(),
		ExpiresAt:      leafTmpl.NotAfter.Unix(),
	}
	record.current = rec
	return rec
}

func seedChain(certPEM, keyPEM []byte) *x509_pb.X509CertChain {
	id := stableID("le-seed", certPEM)
	return &x509_pb.X509CertChain{
		Id: id,
		Chain: []*x509_pb.X509Cert{{
			Id:     id,
			Base64: base64.RawURLEncoding.EncodeToString(certPEM),
		}},
		Key: &key_pb.Key{
			Id:      id,
			Base64:  base64.RawURLEncoding.EncodeToString(keyPEM),
			Created: time.Now().Unix(),
		},
	}
}

// waitForChainPrefix polls the fake kernel for the first write whose certificate
// chain id carries prefix. Polling is the test's own business; the code under test
// is event-driven, and the timeout is what proves it.
func waitForChainPrefix(t *testing.T, fake *fakeCertData, prefix string, within time.Duration) *letsencrypt_pb.LetsEncryptCertData {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, w := range fake.writes() {
			if strings.HasPrefix(w.GetTlsCert().GetId(), prefix) {
				return w
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}
