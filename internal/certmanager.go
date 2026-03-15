package internal

import (
	"context"
	crtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"
	key_pb "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/key"
	x509_pb "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/x509"
	letsencrypt_pb "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/services/letsencrypt"
	"gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/sm"
	"go.uber.org/zap"
)

// CertManager handles Let's Encrypt certificate provisioning and renewal,
// storing the resulting X509CertPair in kernel for gateway to consume.
type CertManager struct {
	cfg     *letsencrypt_pb.Config
	sm      *sm.ServiceManager
	storage *Storage
}

func NewCertManager(cfg *letsencrypt_pb.Config, s *sm.ServiceManager) (*CertManager, error) {
	return &CertManager{
		cfg:     cfg,
		sm:      s,
		storage: NewStorage(),
	}, nil
}

// Run starts the ACME HTTP challenge server, provisions/renews the certificate,
// and writes the result to kernel. Blocks until ctx is cancelled.
func (cm *CertManager) Run(ctx context.Context) error {
	// Restore CertMagic state from kernel if available.
	if err := cm.restoreState(ctx); err != nil {
		zap.L().Warn("Failed to restore CertMagic state, starting fresh", zap.Error(err))
	}

	// Configure CertMagic.
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	certmagic.Default.Storage = cm.storage

	email := cm.cfg.LetsEncryptEmail
	if email == "" {
		email = "admin@" + cm.cfg.Fqdn
	}
	certmagic.DefaultACME.Email = email

	magic := certmagic.NewDefault()

	// Start HTTP server for ACME HTTP-01 challenges.
	httpAddr := fmt.Sprintf("%s:%d", cm.cfg.HttpListener.Host, cm.cfg.HttpListener.Port)
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: certmagic.DefaultACME.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})),
	}

	go func() {
		zap.L().Info("Starting HTTP challenge server", zap.String("addr", httpAddr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("HTTP challenge server failed", zap.Error(err))
		}
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	// Provision certificate.
	zap.L().Info("Requesting certificate", zap.String("fqdn", cm.cfg.Fqdn), zap.String("email", email))
	if err := magic.ManageSync(ctx, []string{cm.cfg.Fqdn}); err != nil {
		return fmt.Errorf("certmagic ManageSync: %w", err)
	}
	zap.L().Info("Certificate provisioned successfully")

	// Extract and store the certificate.
	if err := cm.extractAndStore(ctx, magic); err != nil {
		return fmt.Errorf("storing certificate: %w", err)
	}

	// Renewal loop — CertMagic handles renewal internally via ManageSync,
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
		case <-ticker.C:
			if err := cm.extractAndStore(ctx, magic); err != nil {
				zap.L().Error("Failed to store renewed certificate", zap.Error(err))
			}
		}
	}
}

// extractAndStore extracts the current certificate from CertMagic and writes
// the X509CertPair + CertMagic state to kernel.
func (cm *CertManager) extractAndStore(ctx context.Context, magic *certmagic.Config) error {
	// Get the certificate from CertMagic.
	cert, err := magic.CacheManagedCertificate(ctx, cm.cfg.Fqdn)
	if err != nil {
		return fmt.Errorf("getting cached certificate: %w", err)
	}

	if len(cert.Certificate.Certificate) == 0 {
		return fmt.Errorf("no certificate data for %s", cm.cfg.Fqdn)
	}

	// Build X509CertPair proto from tls.Certificate.
	certPair, err := tlsCertToProto(&cert.Certificate)
	if err != nil {
		return fmt.Errorf("converting certificate: %w", err)
	}

	// Build CertMagic state snapshot.
	certmagicState := cm.storage.ToProto()

	// Write to kernel.
	certData := &letsencrypt_pb.LetsEncryptCertData{
		TlsCert:         certPair,
		CertmagicState:  certmagicState,
		LastRenewed:     time.Now().Unix(),
		Fqdn:            cm.cfg.Fqdn,
	}

	if _, err := cm.sm.StateClients().Services().LetsEncryptState().CertData().Set(ctx, certData); err != nil {
		return fmt.Errorf("writing to kernel: %w", err)
	}

	zap.L().Info("Certificate stored in kernel",
		zap.String("fqdn", cm.cfg.Fqdn),
		zap.Time("expires", cert.Leaf.NotAfter))

	return nil
}

// restoreState loads CertMagic state from kernel and restores it into the
// in-memory storage, so CertMagic doesn't re-provision on restart.
func (cm *CertManager) restoreState(ctx context.Context) error {
	data, err := cm.sm.StateClients().Services().LetsEncryptState().CertData().Fetch(ctx)
	if err != nil {
		return err
	}
	if data == nil || data.CertmagicState == nil {
		return nil
	}

	cm.storage.FromProto(data.CertmagicState)
	zap.L().Info("Restored CertMagic state from kernel",
		zap.String("fqdn", data.Fqdn),
		zap.Time("last_renewed", time.Unix(data.LastRenewed, 0)))
	return nil
}

// tlsCertToProto converts a tls.Certificate to an x509.X509CertPair proto.
func tlsCertToProto(cert *crtls.Certificate) (*x509_pb.X509CertPair, error) {
	// Encode the leaf certificate to PEM then base64.
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	certB64 := base64.StdEncoding.EncodeToString(certPEM)

	// Encode the private key as PKCS8.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyB64 := base64.StdEncoding.EncodeToString(keyPEM)

	return &x509_pb.X509CertPair{
		Key: &key_pb.Key{
			Base64: keyB64,
		},
		Cert: &x509_pb.X509Cert{
			Base64: certB64,
		},
	}, nil
}
