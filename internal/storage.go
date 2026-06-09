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
}

func NewStorage() *Storage {
	return &Storage{
		root: &letsencrypt_pb.CertMagicState{
			IsDir:    true,
			Children: make(map[string]*letsencrypt_pb.CertMagicState),
		},
	}
}

// ToProto returns a deep copy of the storage tree for persistence.
func (s *Storage) ToProto() *letsencrypt_pb.CertMagicState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTree(s.root)
}

// FromProto restores the storage tree from a proto snapshot.
func (s *Storage) FromProto(state *letsencrypt_pb.CertMagicState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state != nil {
		s.root = cloneTree(state)
	}
}

func (s *Storage) Store(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePath(key)
	node := s.getNode(key)
	if node == nil {
		return fmt.Errorf("failed to store key: %s", key)
	}
	node.Value = value
	node.ModTime = time.Now().Unix()
	node.IsDir = false
	return nil
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

var _ certmagic.Storage = (*Storage)(nil)
