package internal

import (
	"context"
	crtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"
	key_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/tacplus/types/libs/key"
	x509_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/tacplus/types/libs/x509"
	kernel_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/tacplus/types/services/kernel"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/tacplus/types/services/letsencrypt"
	"gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/tacplus/s2sm"
	"go.uber.org/zap"
)

// CertManager handles Let's Encrypt certificate provisioning and renewal,
// storing the resulting X509CertChain in kernel for gateway to consume.
type CertManager struct {
	cfg     *letsencrypt_pb.Config
	sm      *sm.ServiceManager
	fqdn    string
	storage *Storage
}

func NewCertManager(cfg *letsencrypt_pb.Config, s *sm.ServiceManager, fqdn string) (*CertManager, error) {
	return &CertManager{
		cfg:     cfg,
		sm:      s,
		fqdn:    fqdn,
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
		email = "admin@" + cm.fqdn
	}
	certmagic.DefaultACME.Email = email

	// AltHTTPPort tells certmagic's httpSolver to bind this port for ACME HTTP-01
	// challenges instead of the default port 80. The k8s LoadBalancer routes
	// external port 80 → pod port AltHTTPPort, allowing a non-root container to
	// participate in HTTP-01 validation.
	certmagic.DefaultACME.AltHTTPPort = int(cm.cfg.HttpListener.Port)

	magic := certmagic.NewDefault()

	// Provision certificate.
	zap.L().Info("Requesting certificate", zap.String("fqdn", cm.fqdn), zap.String("email", email))
	if err := magic.ManageSync(ctx, []string{cm.fqdn}); err != nil {
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
// the X509CertChain + CertMagic state to kernel.
func (cm *CertManager) extractAndStore(ctx context.Context, magic *certmagic.Config) error {
	// Get the certificate from CertMagic.
	cert, err := magic.CacheManagedCertificate(ctx, cm.fqdn)
	if err != nil {
		return fmt.Errorf("getting cached certificate: %w", err)
	}

	if len(cert.Certificate.Certificate) == 0 {
		return fmt.Errorf("no certificate data for %s", cm.fqdn)
	}

	// Build X509CertChain proto from tls.Certificate.
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
		Fqdn:            cm.fqdn,
	}

	if _, err := cm.sm.StateClients().Services().LetsEncryptState().CertData().Set(ctx, certData); err != nil {
		return fmt.Errorf("writing to kernel LetsEncryptState: %w", err)
	}

	// Also write into GatewayTlsState.AcmeCerts so the gateway's WatchAllCerts
	// fires with the newly obtained certificate (AllCerts = ConfigCerts ∪ AcmeCerts).
	gatewayTlsCert := &kernel_pb.GatewayTlsCert{
		Domain:    cm.fqdn,
		CertChain: certPair,
	}
	if _, err := cm.sm.StateClients().Services().GatewayTlsState().StateStub().PutAcmeCerts(ctx, &kernel_pb.AcmeCertsPutRequest{
		Key:   cm.fqdn,
		Value: gatewayTlsCert,
	}); err != nil {
		return fmt.Errorf("writing to kernel GatewayTlsState: %w", err)
	}

	zap.L().Info("Certificate stored in kernel",
		zap.String("fqdn", cm.fqdn),
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

	// Build the certificate chain (leaf + intermediates).
	chain := make([]*x509_pb.X509Cert, len(derChain))
	for i, derBytes := range derChain {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})
		chain[i] = &x509_pb.X509Cert{
			Base64: base64.RawURLEncoding.EncodeToString(certPEM),
		}
	}

	// Encode the private key as PKCS8.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return &x509_pb.X509CertChain{
		Chain: chain,
		Key: &key_pb.Key{
			Base64: base64.RawURLEncoding.EncodeToString(keyPEM),
		},
	}, nil
}
