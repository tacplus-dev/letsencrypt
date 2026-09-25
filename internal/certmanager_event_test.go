package internal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	host_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/sys/host"
)

// signingIssuer stands in for the ACME CA and succeeds, signing whatever CSR
// certmagic hands it with a throwaway CA generated per test. It is installed
// through certmagic.Default.Issuers, which newWithCache leaves alone when it is
// non-nil, so no request ever leaves the process.
type signingIssuer struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newSigningIssuer(t *testing.T) *signingIssuer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "letsencrypt test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return &signingIssuer{caKey: caKey, caCert: caCert}
}

// Issue signs csr. The leaf deliberately carries no IssuingCertificateURL and no
// OCSPServer, so neither certmagic's OCSP stapling nor fetchIntermediates makes
// a network call while the test runs.
func (s *signingIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

func (s *signingIssuer) IssuerKey() string { return "test-signing-issuer" }

// The defect this guards: ManageAsync returns before the obtain finishes, and
// the only thing that used to re-run extractAndStore afterwards was the renewal
// ticker. With RenewalCheckIntervalSeconds at its deployed value of 3600, a
// certificate certmagic had already obtained sat in process memory for up to an
// hour — the gateway serving the fallback cert all that while, and a pod restart
// in the window losing the certificate and costing another of Let's Encrypt's 5
// duplicate certificates per week. The certificate must reach kernel on the
// obtain, so the ticker interval here is set long enough that a pass cannot
// possibly be the ticker's work.
func TestCertificateReachesKernelOnObtainNotOnTick(t *testing.T) {
	installTestIssuer(t, newSigningIssuer(t))

	// certmagic.NewDefault shares one process-global certificate cache, and
	// manageOne returns without emitting anything for a name already managed in
	// it. A name unique to this run keeps the test honest under -count=N and
	// alongside any other test that drives Run.
	hostname := fmt.Sprintf("obtain-%d.example.test", time.Now().UnixNano())

	fake := &fakeCertData{}
	cm := &CertManager{
		cfg: &letsencrypt_pb.Config{
			LetsEncryptEmail:            "admin@example.test",
			HttpListener:                &host_pb.Host{Host: "127.0.0.1", Port: 0},
			RenewalCheckIntervalSeconds: 3600,
		},
		hostnames:  []string{hostname},
		storage:    NewStorage(),
		certData:   fake,
		certRecord: &fakeCertRecord{},
		certSetID:  certSetID([]string{hostname}),
	}
	cm.storage.SetAccountStoreHook(cm.persistAccount)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	stored := waitForStoredCert(t, fake, 15*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	// What reached kernel has to be the real certificate, not an empty shell: the
	// gateway reads TlsCert straight out of this message.
	if len(stored.TlsCert.Chain) == 0 {
		t.Fatal("stored certificate chain is empty")
	}
	if stored.TlsCert.Key == nil {
		t.Error("stored certificate carries no private key")
	}
	if stored.LastRenewed == 0 {
		t.Error("stored certificate has no LastRenewed")
	}
	if got := stored.Hostnames; len(got) != 1 || got[0] != hostname {
		t.Errorf("stored hostnames = %v, want [%s]", got, hostname)
	}
}

// The hook must not hand certmagic an error: certmagic reads a non-nil OnEvent
// return as advice to abort the event, and a kernel write that failed is not a
// reason to abort issuance.
func TestCertMagicEventHookNeverErrors(t *testing.T) {
	changed := make(chan struct{}, 1)
	hook := certMagicEventHook(changed)

	for _, event := range []string{"cert_obtained", "cached_managed_cert", "cert_failed"} {
		if err := hook(context.Background(), event, nil); err != nil {
			t.Errorf("hook returned %v for %s, want nil", err, event)
		}
	}

	// One signal is queued; the rest coalesce into it rather than blocking
	// certmagic, which calls OnEvent synchronously.
	if len(changed) != 1 {
		t.Errorf("queued signals = %d, want 1", len(changed))
	}
}

func TestCertMagicEventHookIgnoresUnrelatedEvents(t *testing.T) {
	changed := make(chan struct{}, 1)
	hook := certMagicEventHook(changed)

	for _, event := range []string{"cert_obtaining", "cert_failed", "cached_unmanaged_cert"} {
		if err := hook(context.Background(), event, nil); err != nil {
			t.Fatalf("hook returned %v for %s", err, event)
		}
	}
	if len(changed) != 0 {
		t.Error("an event unrelated to a managed certificate scheduled an extract")
	}
}

// waitForStoredCert polls the fake kernel for the first write carrying a
// certificate. Polling is the test's own business here; the code under test is
// event-driven, and the timeout is what proves it — it is far shorter than the
// renewal check interval the manager is configured with.
func waitForStoredCert(t *testing.T, fake *fakeCertData, within time.Duration) *letsencrypt_pb.LetsEncryptCertData {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, w := range fake.writes() {
			if w.TlsCert != nil {
				return w
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no certificate reached kernel within %s, though the renewal check interval is %s away",
		within, time.Hour)
	return nil
}
