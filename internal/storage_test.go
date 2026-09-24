package internal

import (
	"context"
	"testing"

	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
)

// TestFromProtoEmptyDefaultKeepsRootDirectory covers first-ever enablement: kernel
// has never been written, so it returns the generated default for cert data — an
// empty but non-nil CertMagicState with IsDir false. Loading that must not strip
// the root's directory-ness, or certmagic's storage read/write self-test fails
// with "failed to store key: rw_test_..." and the service crash-loops.
func TestFromProtoEmptyDefaultKeepsRootDirectory(t *testing.T) {
	s := NewStorage()
	s.FromProto(&letsencrypt_pb.CertMagicState{})

	ctx := context.Background()
	const key = "rw_test_0123456789abcdef"
	want := []byte("contents")

	if err := s.Store(ctx, key, want); err != nil {
		t.Fatalf("Store(%q) after loading empty default: %v", key, err)
	}
	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load(%q): %v", key, err)
	}
	if string(got) != string(want) {
		t.Errorf("Load(%q) = %q, want %q", key, got, want)
	}

	// Nested keys go through the same root, so exercise one too.
	nested := "acme/acme-v02.api.letsencrypt.org/users/admin@example.com/admin.json"
	if err := s.Store(ctx, nested, []byte("{}")); err != nil {
		t.Fatalf("Store(%q) after loading empty default: %v", nested, err)
	}
	if !s.Exists(ctx, nested) {
		t.Errorf("Exists(%q) = false, want true", nested)
	}
}

// TestFromProtoPreservesLoadedTree checks the restore path still round-trips a
// real snapshot rather than being flattened by the root repair above.
func TestFromProtoPreservesLoadedTree(t *testing.T) {
	src := NewStorage()
	ctx := context.Background()
	if err := src.Store(ctx, "certificates/example.com/example.com.crt", []byte("pem")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	dst := NewStorage()
	dst.FromProto(src.ToProto())

	got, err := dst.Load(ctx, "certificates/example.com/example.com.crt")
	if err != nil {
		t.Fatalf("Load after FromProto: %v", err)
	}
	if string(got) != "pem" {
		t.Errorf("Load = %q, want %q", got, "pem")
	}
}
