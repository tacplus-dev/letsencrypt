package internal

import (
	"context"
	"crypto/sha256"
	crtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/s2sm"
	letsencrypt_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	key_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/key"
	x509_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/x509"
	"go.uber.org/zap"
)

// certDataStore is the part of the tacplus-generated LetsEncryptState CertData
// wrapper this package uses. The generated *CertDataWrapper satisfies it as-is;
// the interface exists only so tests can substitute a fake kernel.
type certDataStore interface {
	Fetch(ctx context.Context) (*letsencrypt_pb.LetsEncryptCertData, error)
	Set(ctx context.Context, v *letsencrypt_pb.LetsEncryptCertData) (*letsencrypt_pb.LetsEncryptCertData, error)
}

// CertManager handles Let's Encrypt certificate provisioning and renewal, storing
// the resulting X509CertChain in the LetsEncryptCert stratum record (the durable
// copy) and mirroring it into kernel for gateway to consume.
type CertManager struct {
	cfg       *letsencrypt_pb.Config
	sm        *sm.ServiceManager
	hostnames []string
	storage   *Storage
	certData  certDataStore

	// certRecord is the DURABLE copy — the LetsEncryptCert stratum record. certData
	// above is its live mirror in kernel, which the gateway watches and which holds
	// nothing durably (decisions/
	// kernel-no-durability-user-data-to-stratum-2026-09-25.md). Every write goes
	// here first and to certData second.
	certRecord certRecordStore
	// certSetID keys the record: the digest of the sorted hostname list. Computed
	// once, because every read and every write uses it.
	certSetID string

	// mu guards lastCertData, which the account-store hook reads from a
	// certmagic goroutine while Run writes it.
	mu           sync.Mutex
	lastCertData *letsencrypt_pb.LetsEncryptCertData
}

func NewCertManager(cfg *letsencrypt_pb.Config, s *sm.ServiceManager, hostnames []string) (*CertManager, error) {
	id := certSetID(hostnames)
	return &CertManager{
		cfg:       cfg,
		sm:        s,
		hostnames: hostnames,
		storage:   NewStorage(),
		certData:  s.StateClients().Services().LetsEncryptState().CertData(),
		certRecord: &recordStore{
			records:   s.Grpc().Clients().Vservices().RecordMapClient(),
			publish:   s.CreateLetsencryptLetsEncryptCertBusStreamPublisher(),
			certSetID: id,
		},
		certSetID: id,
	}, nil
}

// Run starts the ACME HTTP challenge server, provisions/renews the certificate,
// and writes the result to kernel. Blocks until ctx is cancelled.
func (cm *CertManager) Run(ctx context.Context) error {
	// Restore from the DURABLE copy in stratum, falling back to the kernel mirror.
	// A usable certificate found here is what makes a cold start skip ACME
	// entirely: the certificate lands in certmagic's storage before ManageAsync is
	// called below, so certmagic has nothing to obtain.
	if err := cm.restoreState(ctx); err != nil {
		zap.L().Warn("Failed to restore CertMagic state, starting fresh", zap.Error(err))
	}

	// Configure CertMagic.
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	certmagic.Default.Storage = cm.storage
	// Push the ACME account to kernel the moment certmagic registers it. Waiting
	// for ManageSync to finish means a crash during issuance loses the account,
	// and the next boot registers another one — Let's Encrypt allows only 10 new
	// registrations per 3 hours per IP, which a crash-loop exhausts.
	cm.storage.SetAccountStoreHook(cm.persistAccount)
	// Port 443 belongs to the gateway, not this pod, so TLS-ALPN-01 (which
	// must answer the challenge over TLS on 443) can never succeed here —
	// HTTP-01 is the only challenge type that fits this deployment.
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	email := cm.cfg.LetsEncryptEmail
	if email == "" {
		email = "admin@" + cm.hostnames[0]
	}
	certmagic.DefaultACME.Email = email

	// AltHTTPPort tells certmagic's httpSolver to bind this port for ACME HTTP-01
	// challenges instead of the default port 80. The k8s LoadBalancer routes
	// external port 80 → pod port AltHTTPPort, allowing a non-root container to
	// participate in HTTP-01 validation.
	certmagic.DefaultACME.AltHTTPPort = int(cm.cfg.HttpListener.Port)

	// certmagic emits cert_obtained the moment an obtain or a renewal lands in its
	// storage, and cached_managed_cert whenever a managed certificate is loaded
	// into its in-memory cache (which is also how the restore-from-kernel path on
	// boot surfaces a certificate that was already obtained). Those events are the
	// only in-process signal that a certificate now exists: ManageAsync returns
	// before the obtain runs, so without them the first extract after a cold-start
	// obtain is the renewal ticker's, up to RenewalCheckIntervalSeconds later. That
	// is an hour of the gateway serving the fallback cluster-CA cert, and an hour in
	// which a pod restart throws the obtained certificate away and has to open
	// another ACME order — 5 duplicate certificates per week per identifier is all
	// Let's Encrypt allows.
	//
	// The hook only signals; the loop below does the extract. It must not extract
	// inline for two reasons:
	//   - certmagic calls OnEvent synchronously from inside the obtain path (see
	//     its doc comment on Config.OnEvent), and an extract is a gRPC round trip
	//     to kernel, which would stall issuance for as long as it is in flight.
	//   - extractAndStore calls CacheManagedCertificate, which itself emits
	//     cached_managed_cert on the calling goroutine, so a hook that extracted
	//     directly would recurse without bound.
	//
	// Set on certmagic.Default rather than on magic: the default certificate cache
	// builds a fresh NewDefault() config to renew with (see NewDefault's
	// GetConfigForCert), so a hook set only on magic would never see a renewal's
	// cert_obtained.
	certChanged := make(chan struct{}, 1)
	certmagic.Default.OnEvent = certMagicEventHook(certChanged)

	magic := certmagic.NewDefault()

	// extract wraps extractAndStore to drop the cached_managed_cert signal that its
	// own CacheManagedCertificate call leaves in certChanged. Without that, every
	// extract would schedule the next one and the loop would spin.
	extract := func() error {
		err := cm.extractAndStore(ctx, magic)
		select {
		case <-certChanged:
		default:
		}
		return err
	}

	// Provision certificates for the configured hostnames. certmagic obtains one
	// single-name certificate per hostname, not one multi-SAN certificate.
	//
	// ManageAsync, not ManageSync: ManageSync returns the first ACME error, and
	// that error used to propagate out of Run into main's log.Fatalf. The process
	// exited, k8s restarted the pod, and the fresh process issued a brand new ACME
	// order — so every restart burned one of Let's Encrypt's 5 failed
	// authorizations per hour per identifier and threw away certmagic's backoff.
	// ManageAsync hands the obtain to certmagic's own retry machinery (exponential
	// backoff, up to about 30 days; see async.go retryIntervals) and returns before
	// the certificate exists, which makes a failed attempt a logged condition
	// rather than a fatal one. Only ctx cancellation ends Run from here on.
	zap.L().Info("Requesting certificate", zap.Strings("hostnames", cm.hostnames), zap.String("email", email))
	if err := magic.ManageAsync(ctx, cm.hostnames); err != nil {
		// ManageAsync only returns errors raised before any ACME transaction
		// started — a misconfiguration or unreadable storage, not a failed obtain.
		// Nothing is queued to retry in that case, so it stays fatal: it costs no
		// rate-limit budget and needs an operator, not a backoff.
		return fmt.Errorf("certmagic ManageAsync: %w", err)
	}

	// The certificate is not ready yet — ManageAsync returns while the obtain is
	// still running in the background — so this first extract is expected to fail
	// on a cold start. Log it and fall through to the loop below, which extracts as
	// soon as certmagic reports a certificate and again on every renewal check.
	if err := extract(); err != nil {
		zap.L().Info("Certificate not available yet; waiting for certmagic to obtain it", zap.Error(err))
	}

	// Renewal loop — CertMagic obtains and renews in the background,
	// but we need to periodically re-extract and push to kernel.
	interval := time.Duration(cm.cfg.RenewalCheckIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	zap.L().Info("Entering renewal check loop", zap.Duration("interval", interval))
	for {
		select {
		case <-ctx.Done():
			zap.L().Info("Shutting down letsencrypt")
			return nil
		case <-certChanged:
			// certmagic just obtained, renewed or cached a certificate. Kept
			// separate from the ticker case so a transient kernel failure here is a
			// warning, not an error: the ticker below re-extracts regardless.
			if err := extract(); err != nil {
				zap.L().Warn("Certificate event fired but the certificate could not be stored; the renewal check will retry", zap.Error(err))
			}
		case <-ticker.C:
			// Belt and braces behind the event hook: certmagic drops an event if
			// nothing is listening at that instant, and this loop is not listening
			// while it is extracting.
			if err := extract(); err != nil {
				zap.L().Error("Failed to store renewed certificate", zap.Error(err))
			}
		}
	}
}

// certMagicEventHook returns a certmagic Config.OnEvent callback that pokes
// changed whenever an event means a certificate may now be available in
// certmagic's storage. The send is non-blocking: certmagic calls OnEvent
// synchronously, and a full channel already means an extract is pending. It
// never returns an error, because certmagic reads a non-nil return as advice to
// abort the event (see Config.OnEvent's doc comment) and neither event here is
// abortable or a reason to abort.
func certMagicEventHook(changed chan<- struct{}) func(context.Context, string, map[string]any) error {
	return func(_ context.Context, event string, _ map[string]any) error {
		switch event {
		case "cert_obtained", "cached_managed_cert":
			select {
			case changed <- struct{}{}:
			default:
			}
		}
		return nil
	}
}

// extractAndStore extracts the current certificate from CertMagic and writes
// the X509CertChain + CertMagic state to kernel.
func (cm *CertManager) extractAndStore(ctx context.Context, magic *certmagic.Config) error {
	// Get the certificate from CertMagic using the primary hostname.
	// CertMagic provisions one single-name cert per managed hostname, so this
	// returns hostnames[0]'s cert only; it does not cover any other hostname.
	cert, err := magic.CacheManagedCertificate(ctx, cm.hostnames[0])
	if err != nil {
		return fmt.Errorf("getting cached certificate: %w", err)
	}

	if len(cert.Certificate.Certificate) == 0 {
		return fmt.Errorf("no certificate data for %s", cm.hostnames[0])
	}

	// Build X509CertChain proto from tls.Certificate.
	certPair, err := tlsCertToProto(&cert.Certificate)
	if err != nil {
		return fmt.Errorf("converting certificate: %w", err)
	}

	// Build CertMagic state snapshot.
	certmagicState := cm.storage.ToProto()

	// Write to kernel. Gateway subscribes RO to LetsEncryptState to obtain the cert.
	certData := &letsencrypt_pb.LetsEncryptCertData{
		TlsCert:        certPair,
		CertmagicState: certmagicState,
		LastRenewed:    time.Now().Unix(),
		Hostnames:      cm.hostnames,
	}

	if err := cm.store(ctx, certData); err != nil {
		return err
	}

	zap.L().Info("Certificate stored",
		zap.Strings("hostnames", cm.hostnames),
		zap.String("cert_set_id", cm.certSetID),
		zap.Time("expires", cert.Leaf.NotAfter))

	return nil
}

// store writes certData to stratum FIRST and to kernel SECOND, and stops at the
// first failure.
//
// The order is the design, not a preference: kernel holds nothing durably, so a
// kernel write that landed while the record write failed would leave a mirror with
// no durable copy behind it — and the next start, reading stratum, would obtain a
// fresh certificate while the gateway was still serving the one kernel remembers.
// Failing here instead leaves both stores on their previous contents and reports
// the error to Run's caller, where the certChanged case warns and the renewal
// ticker retries. That is this service's existing convention for a failed store
// (see Run's loop) and the same posture ManageAsync's backoff takes: a retryable
// condition is logged and retried, never fatal and never silently skipped.
func (cm *CertManager) store(ctx context.Context, certData *letsencrypt_pb.LetsEncryptCertData) error {
	if err := cm.certRecord.Publish(ctx, cm.certRecordFromCertData(certData)); err != nil {
		return fmt.Errorf("writing LetsEncryptCert stratum record: %w", err)
	}
	if _, err := cm.certData.Set(ctx, certData); err != nil {
		return fmt.Errorf("writing to kernel LetsEncryptState: %w", err)
	}
	cm.setLastCertData(certData)
	return nil
}

// restoreState loads the CertMagic tree into the in-memory storage so CertMagic
// does not re-provision on restart, and repopulates the kernel mirror from it.
//
// STRATUM IS THE SOURCE. The record is the durable copy; the kernel mirror holds
// nothing across a full kernel restart and is read only as a fallback for the one
// case the record cannot cover — a mirror written by a build that predates the
// record. Restoring the tree is what carries the ACME ACCOUNT across a restart,
// so it happens whether or not the certificate in it is still usable: an expired
// certificate should cost a renewal, never a second ACME registration.
func (cm *CertManager) restoreState(ctx context.Context) error {
	rec, recErr := cm.certRecord.Fetch(ctx)
	if recErr != nil {
		zap.L().Warn("Failed to read LetsEncryptCert stratum record; falling back to the kernel mirror",
			zap.String("cert_set_id", cm.certSetID), zap.Error(recErr))
	}
	if rec != nil && rec.GetCertmagicState() != nil {
		usable, err := recordUsable(rec, time.Now())
		if err != nil {
			zap.L().Warn("LetsEncryptCert record holds a certificate that will not parse; treating it as absent",
				zap.String("cert_set_id", cm.certSetID), zap.Error(err))
		}
		cm.storage.FromProto(rec.GetCertmagicState())
		certData := &letsencrypt_pb.LetsEncryptCertData{
			TlsCert:        rec.GetTlsCert(),
			CertmagicState: rec.GetCertmagicState(),
			LastRenewed:    rec.GetIssuedAt(),
			Hostnames:      rec.GetHostnames(),
		}
		// Mirror straight into kernel, NOT through store: the record this came from
		// is already the durable copy, and republishing it would be a write with
		// nothing to say.
		if _, err := cm.certData.Set(ctx, certData); err != nil {
			return fmt.Errorf("mirroring LetsEncryptCert record into kernel LetsEncryptState: %w", err)
		}
		cm.setLastCertData(certData)
		zap.L().Info("Restored from LetsEncryptCert stratum record",
			zap.String("cert_set_id", cm.certSetID),
			zap.Strings("hostnames", rec.GetHostnames()),
			zap.Bool("certificate_usable", usable),
			zap.Time("expires", time.Unix(rec.GetExpiresAt(), 0)))
		return nil
	}

	data, err := cm.certData.Fetch(ctx)
	if err != nil {
		return err
	}
	if data == nil || data.CertmagicState == nil {
		return nil
	}

	cm.setLastCertData(data)
	cm.storage.FromProto(data.CertmagicState)
	zap.L().Info("No LetsEncryptCert record; restored CertMagic state from the kernel mirror",
		zap.Strings("hostnames", data.Hostnames),
		zap.Time("last_renewed", time.Unix(data.LastRenewed, 0)))
	return nil
}

func (cm *CertManager) setLastCertData(data *letsencrypt_pb.LetsEncryptCertData) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.lastCertData = data
}

// persistAccount is the Storage account-store hook: it flushes the CertMagic
// tree to kernel as soon as a complete ACME account lands in it, so a crash
// before issuance finishes does not throw the account away. Called from a
// certmagic goroutine; a failure here must not fail the storage write, because
// issuance can still succeed and extractAndStore will persist the account then.
// "Persist" now means the stratum record, with kernel written after it as the
// mirror — kernel is not a durability layer.
func (cm *CertManager) persistAccount(ctx context.Context, key string) {
	if err := cm.flushCertMagicState(ctx); err != nil {
		zap.L().Warn("Failed to persist ACME account; a crash before issuance completes will lose it",
			zap.String("storage_key", key), zap.Error(err))
		return
	}
	zap.L().Info("ACME account persisted to the LetsEncryptCert record", zap.String("storage_key", key))
}

// flushCertMagicState writes the current CertMagic tree to stratum and then to
// kernel, carrying over the certificate fields from the CertData already there.
// Set replaces the whole message and the gateway serves TlsCert out of it, so a
// flush that dropped those fields would take the live certificate away from the
// gateway.
//
// This is the path that makes the ACME ACCOUNT durable, and it is why the record's
// tls_cert is not required: on a first-ever start the account exists minutes before
// any certificate does, and it has to reach stratum then rather than at the end of
// issuance.
func (cm *CertManager) flushCertMagicState(ctx context.Context) error {
	certData := &letsencrypt_pb.LetsEncryptCertData{
		CertmagicState: cm.storage.ToProto(),
		Hostnames:      cm.hostnames,
	}

	cm.mu.Lock()
	last := cm.lastCertData
	cm.mu.Unlock()
	if last != nil {
		certData.TlsCert = last.TlsCert
		certData.LastRenewed = last.LastRenewed
	}

	return cm.store(ctx, certData)
}

// fetchIntermediates attempts to fetch any missing intermediate CA certs from
// the AIA (Authority Information Access) extension of each cert in the chain.
// This ensures the gateway serves the full chain even if CertMagic only stored
// the leaf cert (which can happen with some ACME configurations).
func fetchIntermediates(derChain [][]byte) [][]byte {
	seen := make(map[string]bool)
	for _, d := range derChain {
		seen[string(d)] = true
	}
	result := make([][]byte, len(derChain))
	copy(result, derChain)

	for _, derBytes := range derChain {
		parsed, err := x509.ParseCertificate(derBytes)
		if err != nil {
			continue
		}
		for _, url := range parsed.IssuingCertificateURL {
			body, fetchErr := func() ([]byte, error) {
				resp, err := http.Get(url) //nolint:noctx
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				return io.ReadAll(resp.Body)
			}()
			if fetchErr != nil {
				zap.L().Warn("Failed to fetch intermediate cert", zap.String("url", url), zap.Error(fetchErr))
				continue
			}
			// The AIA issuer URL returns DER-encoded cert.
			if _, err := x509.ParseCertificate(body); err == nil {
				if !seen[string(body)] {
					seen[string(body)] = true
					result = append(result, body)
					zap.L().Info("Fetched intermediate cert from AIA", zap.String("url", url))
				}
			}
		}
	}
	return result
}

// tlsCertToProto converts a tls.Certificate to an x509.X509CertChain proto.
func tlsCertToProto(cert *crtls.Certificate) (*x509_pb.X509CertChain, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}

	// Ensure the chain includes all intermediate CAs (fetch from AIA if missing).
	derChain := fetchIntermediates(cert.Certificate)

	// Encode the private key as PKCS8.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyID := stableID("le-key", keyBytes)
	created := time.Now().Unix()
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		created = leaf.NotBefore.Unix()
	}

	// Build the certificate chain (leaf + intermediates).
	chain := make([]*x509_pb.X509Cert, len(derChain))
	for i, derBytes := range derChain {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})
		certID := stableID("le-cert", derBytes)
		if i == 0 {
			certID = keyID
		}
		chain[i] = &x509_pb.X509Cert{
			Id:     certID,
			Base64: base64.RawURLEncoding.EncodeToString(certPEM),
		}
	}

	return &x509_pb.X509CertChain{
		Id:    stableID("le-chain", derChain[0]),
		Chain: chain,
		Key: &key_pb.Key{
			Id:      keyID,
			Base64:  base64.RawURLEncoding.EncodeToString(keyPEM),
			Created: created,
		},
	}, nil
}

func stableID(prefix string, data []byte) string {
	sum := sha256.Sum256(data)
	return prefix + "-" + hex.EncodeToString(sum[:16])
}
