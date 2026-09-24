package internal

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
)

// Storage implements certmagic.Storage backed by an in-memory tree.
// State is serialized to/from letsencrypt_pb.CertMagicState for persistence in kernel.
type Storage struct {
	mu   sync.Mutex
	root *letsencrypt_pb.CertMagicState

	// onAccountStore, when set, is invoked right after a Store call leaves a
	// complete ACME account (registration + private key) in the tree. It runs
	// with the mutex released so the callback may call ToProto.
	onAccountStore func(ctx context.Context, key string)
}

func NewStorage() *Storage {
	return &Storage{
		root: &letsencrypt_pb.CertMagicState{
			IsDir:    true,
			Children: make(map[string]*letsencrypt_pb.CertMagicState),
		},
	}
}

// SetAccountStoreHook registers fn to run whenever certmagic finishes writing
// an ACME account into this tree. Certificate issuance can take minutes and can
// crash partway; the account registered just before that crash is only durable
// if it is pushed out of this in-memory tree at once, so the hook exists to do
// that without waiting for issuance to complete. Must be called before the
// storage is handed to certmagic.
func (s *Storage) SetAccountStoreHook(fn func(ctx context.Context, key string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAccountStore = fn
}

// ToProto returns a deep copy of the storage tree for persistence.
func (s *Storage) ToProto() *letsencrypt_pb.CertMagicState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTree(s.root)
}

// FromProto restores the storage tree from a proto snapshot. The root is forced
// back to a directory: on first-ever enablement kernel returns the generated
// default, an empty but non-nil CertMagicState with IsDir false, and a
// non-directory root makes getNode fail for every key.
func (s *Storage) FromProto(state *letsencrypt_pb.CertMagicState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state != nil {
		s.root = cloneTree(state)
		s.root.IsDir = true
		if s.root.Children == nil {
			s.root.Children = make(map[string]*letsencrypt_pb.CertMagicState)
		}
	}
}

func (s *Storage) Store(ctx context.Context, key string, value []byte) error {
	hook, err := s.store(key, value)
	if err != nil {
		return err
	}
	if hook != nil {
		hook(ctx, key)
	}
	return nil
}

// store writes the value and reports the account hook to run, if this write
// completed an ACME account. The hook is returned rather than called so it runs
// after the mutex is released.
func (s *Storage) store(key string, value []byte) (func(context.Context, string), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePath(key)
	node := s.getNode(key)
	if node == nil {
		return nil, fmt.Errorf("failed to store key: %s", key)
	}
	node.Value = value
	node.ModTime = time.Now().Unix()
	node.IsDir = false

	if s.onAccountStore != nil && isACMEAccountKey(key) && s.accountCompleteLocked(key) {
		return s.onAccountStore, nil
	}
	return nil, nil
}

func (s *Storage) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node := s.getNode(key)
	if node == nil || node.IsDir {
		return nil, fs.ErrNotExist
	}
	return node.Value, nil
}

func (s *Storage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, file := path.Split(key)
	dir = strings.TrimSuffix(dir, "/")
	parent := s.getNode(dir)
	if parent != nil && parent.IsDir && parent.Children != nil {
		delete(parent.Children, file)
	}
	return nil
}

func (s *Storage) Exists(_ context.Context, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	node := s.getNode(key)
	return node != nil && !node.IsDir
}

func (s *Storage) List(_ context.Context, prefix string, recursive bool) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix = strings.TrimPrefix(prefix, "/")
	node := s.getNode(prefix)
	if node == nil || !node.IsDir {
		return nil, nil
	}
	var results []string
	s.listRecursive(prefix, node, recursive, &results)
	return results, nil
}

func (s *Storage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node := s.getNode(key)
	if node == nil {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   time.Unix(node.ModTime, 0),
		Size:       int64(len(node.Value)),
		IsTerminal: !node.IsDir,
	}, nil
}

// Lock and Unlock are no-ops — letsencrypt runs as a single instance.
func (s *Storage) Lock(_ context.Context, _ string) error   { return nil }
func (s *Storage) Unlock(_ context.Context, _ string) error { return nil }

// isACMEAccountKey reports whether key is one of the two files certmagic writes
// for an ACME account. ACMEIssuer.saveAccount stores them as
//
//	acme/<ca>/users/<email>/<username>.json   (registration)
//	acme/<ca>/users/<email>/<username>.key    (account private key)
//
// The basename is derived from the email address, not fixed, so the extension is
// what identifies each file. Everything else certmagic writes lives under
// acme/<ca>/challenge_tokens or certificates/, and must not trigger a flush.
func isACMEAccountKey(key string) bool {
	parts := strings.Split(strings.TrimPrefix(key, "/"), "/")
	if len(parts) != 5 || parts[0] != prefixACME || parts[2] != acmeUsersDir {
		return false
	}
	ext := path.Ext(parts[4])
	return ext == acmeAccountRegExt || ext == acmeAccountKeyExt
}

// accountCompleteLocked reports whether the account directory holding key now
// contains both the registration and the private key. saveAccount writes them
// one at a time, and an account missing either file is useless on restore
// (certmagic's loadAccount treats it as absent and registers a new account), so
// a flush of only the first half would persist nothing of value.
func (s *Storage) accountCompleteLocked(key string) bool {
	dir := s.getNode(path.Dir(strings.TrimPrefix(key, "/")))
	if dir == nil || !dir.IsDir {
		return false
	}
	var haveReg, haveKey bool
	for name, child := range dir.Children {
		if child == nil || child.IsDir || len(child.Value) == 0 {
			continue
		}
		switch path.Ext(name) {
		case acmeAccountRegExt:
			haveReg = true
		case acmeAccountKeyExt:
			haveKey = true
		}
	}
	return haveReg && haveKey
}

// getNode traverses the tree to find the node at the given path.
func (s *Storage) getNode(key string) *letsencrypt_pb.CertMagicState {
	key = strings.TrimPrefix(key, "/")
	if key == "" || key == "." {
		return s.root
	}
	current := s.root
	for _, part := range strings.Split(key, "/") {
		if part == "" {
			continue
		}
		if current == nil || !current.IsDir || current.Children == nil {
			return nil
		}
		current = current.Children[part]
	}
	return current
}

// ensurePath creates all parent directories and the leaf file node.
func (s *Storage) ensurePath(key string) {
	key = strings.TrimPrefix(key, "/")
	parts := strings.Split(key, "/")

	current := s.root
	// Create parent directories.
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			continue
		}
		if current.Children == nil {
			current.Children = make(map[string]*letsencrypt_pb.CertMagicState)
		}
		if current.Children[part] == nil {
			current.Children[part] = &letsencrypt_pb.CertMagicState{
				IsDir:    true,
				ModTime:  time.Now().Unix(),
				Children: make(map[string]*letsencrypt_pb.CertMagicState),
			}
		}
		current = current.Children[part]
	}

	// Create leaf file node.
	fileName := parts[len(parts)-1]
	if current.Children == nil {
		current.Children = make(map[string]*letsencrypt_pb.CertMagicState)
	}
	if current.Children[fileName] == nil {
		current.Children[fileName] = &letsencrypt_pb.CertMagicState{
			IsDir:   false,
			ModTime: time.Now().Unix(),
		}
	}
}

func (s *Storage) listRecursive(prefix string, node *letsencrypt_pb.CertMagicState, recursive bool, results *[]string) {
	if node == nil || !node.IsDir || node.Children == nil {
		return
	}
	for name, child := range node.Children {
		fullPath := path.Join(prefix, name)
		if child.IsDir {
			if recursive {
				s.listRecursive(fullPath, child, recursive, results)
			}
		} else {
			*results = append(*results, fullPath)
		}
	}
}

// cloneTree deep-copies a CertMagicState tree.
func cloneTree(src *letsencrypt_pb.CertMagicState) *letsencrypt_pb.CertMagicState {
	if src == nil {
		return nil
	}
	dst := &letsencrypt_pb.CertMagicState{
		IsDir:   src.IsDir,
		Value:   append([]byte(nil), src.Value...),
		ModTime: src.ModTime,
	}
	if src.Children != nil {
		dst.Children = make(map[string]*letsencrypt_pb.CertMagicState, len(src.Children))
		for k, v := range src.Children {
			dst.Children[k] = cloneTree(v)
		}
	}
	return dst
}

// Storage key components certmagic uses for ACME account data. These mirror
// certmagic's own unexported prefixACME and storageKeyUsersPrefix.
const (
	prefixACME        = "acme"
	acmeUsersDir      = "users"
	acmeAccountRegExt = ".json"
	acmeAccountKeyExt = ".key"
)

var _ certmagic.Storage = (*Storage)(nil)
