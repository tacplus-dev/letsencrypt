package internal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	letsencrypt_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	x509_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/x509"
)

// fakeCertData is a stand-in for the tacplus-generated CertData wrapper. It
// records every Set so a test can assert what reached kernel and when.
type fakeCertData struct {
	mu      sync.Mutex
	stored  []*letsencrypt_pb.LetsEncryptCertData
	current *letsencrypt_pb.LetsEncryptCertData
	setErr  error
	// order, when set, is the shared write-order log this fake and the fake stratum
	// record both append to. It is what makes "stratum before kernel" assertable.
	order *orderLog
}

func (f *fakeCertData) Fetch(context.Context) (*letsencrypt_pb.LetsEncryptCertData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current, nil
}

func (f *fakeCertData) Set(_ context.Context, v *letsencrypt_pb.LetsEncryptCertData) (*letsencrypt_pb.LetsEncryptCertData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.order.note("kernel")
	prev := f.current
	f.current = v
	f.stored = append(f.stored, v)
	return prev, nil
}

func (f *fakeCertData) writes() []*letsencrypt_pb.LetsEncryptCertData {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*letsencrypt_pb.LetsEncryptCertData(nil), f.stored...)
}

// newTestCertManager builds a CertManager wired to a fake kernel, with the
// account-store hook installed exactly as Run installs it. sm is left nil: no
// path exercised here touches it.
func newTestCertManager(t *testing.T) (*CertManager, *fakeCertData) {
	t.Helper()
	fake := &fakeCertData{}
	cm := &CertManager{
		cfg:        &letsencrypt_pb.Config{},
		hostnames:  []string{"api.example.test"},
		storage:    NewStorage(),
		certData:   fake,
		certRecord: &fakeCertRecord{},
		certSetID:  certSetID([]string{"api.example.test"}),
	}
	cm.storage.SetAccountStoreHook(cm.persistAccount)
	return cm, fake
}

const (
	testAccountDir = "acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.test"
	testAccountReg = testAccountDir + "/admin.json"
	testAccountKey = testAccountDir + "/admin.key"
)

// The incident this guards: the process dies between ACME account registration
// and the end of certificate issuance, so extractAndStore never runs. The
// account must already be in kernel at that point, or the next boot registers a
// brand new one and a crash-loop burns Let's Encrypt's 10-new-accounts-per-3h
// budget.
func TestAccountPersistedBeforeIssuanceCompletes(t *testing.T) {
	cm, fake := newTestCertManager(t)
	ctx := context.Background()

	// certmagic's saveAccount writes the registration first, then the key.
	if err := cm.storage.Store(ctx, testAccountReg, []byte(`{"status":"valid"}`)); err != nil {
		t.Fatalf("storing registration: %v", err)
	}
	// A half-written account is useless on restore, so nothing is flushed yet.
	if got := len(fake.writes()); got != 0 {
		t.Fatalf("flushed on a half-written account: %d writes", got)
	}

	if err := cm.storage.Store(ctx, testAccountKey, []byte("-----BEGIN EC PRIVATE KEY-----")); err != nil {
		t.Fatalf("storing account key: %v", err)
	}

	// Simulated crash: extractAndStore is never called. The account must
	// nonetheless be in kernel already.
	writes := fake.writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 flush once the account was complete, got %d", len(writes))
	}
	state := writes[0].CertmagicState
	if state == nil {
		t.Fatal("flushed CertData carries no CertmagicState")
	}
	for _, key := range []string{testAccountReg, testAccountKey} {
		if !hasKey(state, key) {
			t.Errorf("flushed CertmagicState is missing %s", key)
		}
	}

	// And the flushed state restores into a fresh Storage, which is what the
	// next boot's restoreState does.
	restored := NewStorage()
	restored.FromProto(state)
	if !restored.Exists(ctx, testAccountKey) {
		t.Error("restored storage does not have the account private key")
	}
}

func TestNonAccountWritesDoNotFlush(t *testing.T) {
	cm, fake := newTestCertManager(t)
	ctx := context.Background()

	keys := []string{
		"acme/acme-v02.api.letsencrypt.org-directory/challenge_tokens/api.example.test.json",
		"certificates/acme-v02.api.letsencrypt.org-directory/api.example.test/api.example.test.crt",
		"certificates/acme-v02.api.letsencrypt.org-directory/api.example.test/api.example.test.key",
		"locks/issue_cert_api.example.test.lock",
		"acme/acme-v02.api.letsencrypt.org-directory/users/admin@example.test/extra/nested.json",
	}
	for _, key := range keys {
		if err := cm.storage.Store(ctx, key, []byte("x")); err != nil {
			t.Fatalf("storing %s: %v", key, err)
		}
	}
	if got := len(fake.writes()); got != 0 {
		t.Fatalf("non-account writes triggered %d kernel flushes", got)
	}
}

// A flush must not take the certificate away from the gateway: Set replaces the
// whole CertData message, and the gateway serves TlsCert out of it.
func TestAccountFlushPreservesExistingCert(t *testing.T) {
	cm, fake := newTestCertManager(t)
	ctx := context.Background()

	existing := &letsencrypt_pb.LetsEncryptCertData{
		TlsCert:        &x509_pb.X509CertChain{Id: "existing-chain"},
		CertmagicState: NewStorage().ToProto(),
		LastRenewed:    1234,
		Hostnames:      []string{"api.example.test"},
		Certs:          []*letsencrypt_pb.NamedCert{{Hostname: "api.example.test"}},
	}
	fake.current = existing
	if err := cm.restoreState(ctx); err != nil {
		t.Fatalf("restoreState: %v", err)
	}

	storeCompleteAccount(t, cm, ctx)

	writes := fake.writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 flush, got %d", len(writes))
	}
	if writes[0].TlsCert != existing.TlsCert {
		t.Error("flush dropped the certificate already in kernel")
	}
	if len(writes[0].Certs) != 1 || writes[0].Certs[0] != existing.Certs[0] {
		t.Error("flush dropped the per-hostname certificates already in kernel")
	}
	if writes[0].LastRenewed != existing.LastRenewed {
		t.Errorf("flush dropped LastRenewed: got %d", writes[0].LastRenewed)
	}
}

// A kernel write failure must not fail certmagic's storage write: issuance can
// still succeed, and extractAndStore persists the account at that point.
func TestAccountFlushFailureDoesNotFailStore(t *testing.T) {
	cm, fake := newTestCertManager(t)
	fake.setErr = errors.New("kernel unavailable")
	ctx := context.Background()

	if err := cm.storage.Store(ctx, testAccountReg, []byte("{}")); err != nil {
		t.Fatalf("storing registration: %v", err)
	}
	if err := cm.storage.Store(ctx, testAccountKey, []byte("key")); err != nil {
		t.Fatalf("store returned the flush error: %v", err)
	}
	if !cm.storage.Exists(ctx, testAccountKey) {
		t.Error("account key was not written to storage")
	}
}

func storeCompleteAccount(t *testing.T, cm *CertManager, ctx context.Context) {
	t.Helper()
	if err := cm.storage.Store(ctx, testAccountReg, []byte("{}")); err != nil {
		t.Fatalf("storing registration: %v", err)
	}
	if err := cm.storage.Store(ctx, testAccountKey, []byte("key")); err != nil {
		t.Fatalf("storing account key: %v", err)
	}
}

// hasKey walks a CertMagicState tree looking for a file node at key.
func hasKey(root *letsencrypt_pb.CertMagicState, key string) bool {
	node := root
	for _, part := range strings.Split(key, "/") {
		if node == nil || !node.IsDir {
			return false
		}
		node = node.Children[part]
	}
	return node != nil && !node.IsDir
}
