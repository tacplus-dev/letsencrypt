package internal

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	query_gc "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/s2sm/grpc/clients/vservices/query"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	x509_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/sys/x509"
	query_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/vservices/query"
	"go.uber.org/zap"
)

// certRecordStore is the stratum LetsEncryptCert record, as this package uses it:
// read the one row for the configured hostname set, and write it back. recordStore
// below is the real implementation over the tacplus-generated record plane; the
// interface exists only so tests can substitute a fake stratum.
type certRecordStore interface {
	// Fetch returns the record for the hostname set, or (nil, nil) when stratum
	// holds none.
	Fetch(ctx context.Context) (*letsencrypt_pb.LetsEncryptCert, error)
	// Publish writes the record. A record has no write RPC — it reaches stratum on
	// stratum's own subscription to the record's topic — so this is a publish onto
	// that topic, and it returns once the publish is ACCEPTED, not once stratum has
	// stored the row. See recordStore.Publish.
	Publish(ctx context.Context, rec *letsencrypt_pb.LetsEncryptCert) error
}

// recordStore reads and writes the LetsEncryptCert record through the generated
// record plane: the read half is stratum's RecordMap client (derived from
// (spec.record_read) in letsencrypt.proto), and the write half is the topic
// publisher the ServiceManager exposes for the record's synthesized bus.
// Nothing here speaks to stratum directly.
type recordStore struct {
	records   *query_gc.RecordMapClient
	publish   func(context.Context, *letsencrypt_pb.LetsEncryptCert) error
	certSetID string
}

// Fetch runs the record plane's three-call read lifecycle — open a query over the
// key, pull its single page, close the query — and returns the row.
//
// The query is closed on every path, success included: a standing query left open
// is a predicate stratum keeps evaluating for a caller that has gone away.
func (r *recordStore) Fetch(ctx context.Context) (*letsencrypt_pb.LetsEncryptCert, error) {
	handle, err := r.records.CreateLetsEncryptCertQuery(ctx, &query_pb.OpenLetsEncryptCertQueryRequest{
		Filter: &query_pb.LetsEncryptCertFilter{CertSetId: &r.certSetID},
	})
	if err != nil {
		return nil, fmt.Errorf("opening LetsEncryptCert query: %w", err)
	}
	defer func() {
		if _, delErr := r.records.DeleteLetsEncryptCertQuery(ctx, &query_pb.QueryHandle{QueryId: handle.GetQueryId()}); delErr != nil {
			zap.L().Warn("Failed to close LetsEncryptCert query", zap.Error(delErr))
		}
	}()

	// PageSize 2, not 1: the key is unique, so a second row would mean the plane
	// returned a row for a different hostname set and the read cannot be trusted.
	// Asking for one row could not tell the difference.
	rows, _, _, err := r.records.ListLetsEncryptCertPage(ctx, &query_pb.PullLetsEncryptCertRequest{
		QueryId:  handle.GetQueryId(),
		PageSize: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("reading LetsEncryptCert rows: %w", err)
	}
	switch len(rows) {
	case 0:
		return nil, nil
	case 1:
		return rows[0], nil
	default:
		return nil, fmt.Errorf("LetsEncryptCert key %s matched %d rows", r.certSetID, len(rows))
	}
}

// Publish enqueues the record onto its topic.
//
// WHAT "WRITTEN" MEANS HERE, because it is narrower than it looks: the generated
// publisher hands the record to a bounded background loop that keeps it pending
// until the broker acknowledges it, retrying with backoff — and returns as soon as
// the record is accepted into that queue. There is no generated API in this fleet,
// in any language, that blocks until stratum has the row: a record's only write
// path is its EventBus topic, and both the Go and the Java publisher are
// enqueue-and-retry by design. So an error here means the record was not accepted
// for delivery at all, which is the failure worth refusing to continue past; a
// successful return means delivery is underway and will not be dropped short of
// the process dying.
func (r *recordStore) Publish(ctx context.Context, rec *letsencrypt_pb.LetsEncryptCert) error {
	if err := r.publish(ctx, rec); err != nil {
		return fmt.Errorf("publishing LetsEncryptCert record: %w", err)
	}
	return nil
}

// certSetID is the record's key: a stable digest of the sorted hostname list.
//
// Keyed by the hostname SET rather than a fixed singleton so that changing
// Config.hostnames misses on read and obtains a certificate for the new names. A
// fixed key would find the old row, see an unexpired certificate, and serve names
// the certificate does not cover. Sorted so that reordering the config list is not
// a different certificate.
func certSetID(hostnames []string) string {
	sorted := make([]string, len(hostnames))
	copy(sorted, hostnames)
	sort.Strings(sorted)
	return stableID("le-certset", []byte(strings.Join(sorted, ",")))
}

// sortedHostnames returns hostnames in the order certSetID digested them, which is
// the order the record carries them in.
func sortedHostnames(hostnames []string) []string {
	sorted := make([]string, len(hostnames))
	copy(sorted, hostnames)
	sort.Strings(sorted)
	return sorted
}

// recordUsable reports whether rec holds a certificate this service can serve
// without calling ACME.
//
// The window is certmagic's own, not one invented here: certmagic renews a
// certificate once it enters the last RenewalWindowRatio of its lifetime (default
// one third, DefaultRenewalWindowRatio), so a certificate already inside that
// window is one certmagic would immediately renew, and treating it as usable would
// only mean starting up, loading it, and obtaining anyway. Note that
// renewal_check_interval_seconds is NOT a safety margin — it is how often this
// service re-extracts what certmagic has — so it is deliberately not used here.
func recordUsable(rec *letsencrypt_pb.LetsEncryptCert, now time.Time) (bool, error) {
	if rec == nil || rec.GetTlsCert() == nil || len(rec.GetTlsCert().GetChain()) == 0 {
		return false, nil
	}
	leaf, err := parseLeaf(rec.GetTlsCert())
	if err != nil {
		return false, err
	}
	ratio := certmagic.Default.RenewalWindowRatio
	if ratio == 0 {
		ratio = certmagic.DefaultRenewalWindowRatio
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	renewFrom := leaf.NotAfter.Add(-time.Duration(float64(lifetime) * ratio))
	return now.Before(renewFrom), nil
}

// certRecordFromCertData builds the record from the same CertData the kernel mirror
// receives, so the two cannot describe different certificates. issued_at and
// expires_at come off the leaf, which is the authority on both; a cert-less flush
// (the ACME account hook) leaves them zero.
func (cm *CertManager) certRecordFromCertData(data *letsencrypt_pb.LetsEncryptCertData) *letsencrypt_pb.LetsEncryptCert {
	rec := &letsencrypt_pb.LetsEncryptCert{
		CertSetId:      cm.certSetID,
		TlsCert:        data.GetTlsCert(),
		CertmagicState: data.GetCertmagicState(),
		Hostnames:      sortedHostnames(cm.hostnames),
	}
	if leaf, err := parseLeaf(data.GetTlsCert()); err == nil {
		rec.IssuedAt = leaf.NotBefore.Unix()
		rec.ExpiresAt = leaf.NotAfter.Unix()
	}
	return rec
}

// parseLeaf decodes the leaf certificate out of an X509CertChain. The chain carries
// each cert as a base64url-encoded PEM block (see tlsCertToProto, which writes it),
// and leaf.NotBefore/NotAfter are the only authority on when the certificate is
// valid — x509.X509CertChain carries no timestamps of its own.
func parseLeaf(chain *x509_pb.X509CertChain) (*x509.Certificate, error) {
	if chain == nil || len(chain.GetChain()) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	pemBytes, err := base64.RawURLEncoding.DecodeString(chain.GetChain()[0].GetBase64())
	if err != nil {
		return nil, fmt.Errorf("decoding leaf certificate: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("leaf certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	return leaf, nil
}
