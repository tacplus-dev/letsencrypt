package internal

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	letsencrypt_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	host_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/host"
)

// failingIssuer stands in for the ACME CA and fails every issuance, the way
// Let's Encrypt does when the per-identifier rate limit is exhausted. It is
// installed through certmagic.Default.Issuers, which newWithCache leaves alone
// when it is non-nil, so no request ever leaves the process.
type failingIssuer struct {
	mu       sync.Mutex
	attempts int
	called   chan struct{}
}

func newFailingIssuer() *failingIssuer {
	return &failingIssuer{called: make(chan struct{}, 1)}
}

func (f *failingIssuer) Issue(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	f.mu.Lock()
	f.attempts++
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
	return nil, acmeRateLimitError{}
}

func (f *failingIssuer) IssuerKey() string { return "test-failing-issuer" }

func (f *failingIssuer) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

type acmeRateLimitError struct{}

func (acmeRateLimitError) Error() string {
	return "HTTP 429 urn:ietf:params:acme:error:rateLimited - too many failed authorizations recently"
}

// The incident this guards: a failed ACME attempt used to come back out of
// ManageSync, through Run, and into main's log.Fatalf. The process exited, k8s
// restarted the pod, and the new process opened a brand new ACME order — 11
// restarts, 11 orders, the rate-limit budget gone and certmagic's backoff reset
// every time. A failed obtain must instead leave the process up and running,
// with only ctx cancellation ending Run.
func TestRunSurvivesFailedACMEAttempt(t *testing.T) {
	issuer := newFailingIssuer()
	installTestIssuer(t, issuer)

	fake := &fakeCertData{}
	cm := &CertManager{
		cfg: &letsencrypt_pb.Config{
			LetsEncryptEmail:            "admin@example.test",
			HttpListener:                &host_pb.Host{Host: "127.0.0.1", Port: 0},
			RenewalCheckIntervalSeconds: 1,
		},
		hostnames:  []string{"api.example.test"},
		storage:    NewStorage(),
		certData:   fake,
		certRecord: &fakeCertRecord{},
		certSetID:  certSetID([]string{"api.example.test"}),
	}
	cm.storage.SetAccountStoreHook(cm.persistAccount)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cm.Run(ctx) }()

	// Wait for the ACME attempt to happen and fail. Run is meanwhile expected to
	// have logged the failed extract and entered the renewal check loop.
	select {
	case <-issuer.called:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("issuer was never asked for a certificate")
	}

	// Give Run a moment to reach the renewal loop and tick at least once with no
	// certificate available; neither must end it.
	select {
	case err := <-errCh:
		cancel()
		t.Fatalf("Run returned while the ACME attempt was failing: %v", err)
	case <-time.After(2500 * time.Millisecond):
	}

	// Only shutdown ends Run, and it ends cleanly.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	if got := issuer.attemptCount(); got != 1 {
		t.Errorf("issuer attempts = %d, want 1 (certmagic backs off for a minute before retrying)", got)
	}
	// Nothing was ever obtained, so nothing must have been written to kernel as a
	// certificate.
	for _, w := range fake.writes() {
		if w.TlsCert != nil {
			t.Error("a certificate reached kernel even though issuance failed")
		}
	}
}

// installTestIssuer points certmagic's package-level defaults at issuer and
// restores them when the test finishes. Run mutates these same globals, so the
// save/restore has to cover everything it touches.
func installTestIssuer(t *testing.T, issuer certmagic.Issuer) {
	t.Helper()
	prevIssuers, prevStorage := certmagic.Default.Issuers, certmagic.Default.Storage
	prevOnEvent := certmagic.Default.OnEvent
	prevACME := certmagic.DefaultACME
	t.Cleanup(func() {
		certmagic.Default.Issuers, certmagic.Default.Storage = prevIssuers, prevStorage
		certmagic.Default.OnEvent = prevOnEvent
		certmagic.DefaultACME = prevACME
	})
	certmagic.Default.Issuers = []certmagic.Issuer{issuer}
}
