// Copyright (c) 2024 Second Star Cavalier, LLC.

package webserver

import (
	"context"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"google.golang.org/protobuf/proto"

	webserverProto "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/httpserver"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/errors"
)

// Storage implements certmagic.Storage interface and bridges to the Callback interface.
//
// Storage provides an in-memory certificate storage implementation that synchronizes
// with distributed storage via the Callback interface. It maintains a hierarchical
// tree structure mirroring the filesystem layout used by CertMagic for certificate
// data organization.
//
// # Architecture
//
// The Storage maintains an in-memory tree structure where:
//   - Each node represents either a directory or a file
//   - Directories have IsDir=true and contain a map of child nodes
//   - Files have IsDir=false and contain certificate data in Value field
//   - All operations are synchronized to distributed storage via callbacks
//
// # Thread Safety
//
// Storage is NOT thread-safe by itself. CertMagic handles synchronization through
// the Lock/Unlock methods on the certmagic.Storage interface, which delegate to
// the Callback interface for distributed locking.
//
// # State Persistence
//
// Every mutation operation (Store, Delete) triggers UpdateWebServerState callback,
// ensuring the in-memory state is persisted to shared storage. This allows:
//   - Certificate sharing across multiple server instances
//   - State recovery after server restart
//   - Distributed certificate management
//
// # CertMagic Integration
//
// Storage implements the certmagic.Storage interface completely:
//   - Store: Save certificate data
//   - Load: Retrieve certificate data
//   - Delete: Remove certificate data
//   - Exists: Check if certificate exists
//   - List: List certificates in directory
//   - Stat: Get certificate metadata
//   - Lock: Acquire distributed lock
//   - Unlock: Release distributed lock
type Storage struct {
	callback Callback
	state    *webserverProto.State
}

// NewStorage creates a new Storage instance wrapping the provided callback.
//
// The returned Storage maintains an empty certificate state tree initially.
// State can be restored from persistent storage using SetState() before
// starting certificate operations.
//
// Parameters:
//   - callback: Callback implementation for distributed locking and state persistence
//
// Returns:
//   - *Storage ready to use with CertMagic
//
// Example:
//
//	callback := &MyCallback{db: database, redis: redisClient}
//	storage := webserver.NewStorage(callback)
//
//	// Restore previous state if available
//	if savedState, err := loadStateFromDB(); err == nil {
//	    storage.SetState(savedState)
//	}
//
//	// Use with CertMagic
//	certmagic.Default.Storage = storage
func NewStorage(callback Callback) *Storage {
	return &Storage{
		callback: callback,
		state:    &webserverProto.State{Cert: &webserverProto.CertState{IsDir: true, Certs: make(map[string]*webserverProto.CertState)}},
	}
}

// SetState sets the certificate state, typically used to restore from persistent storage.
//
// This method replaces the entire in-memory state tree with the provided state,
// allowing restoration of certificate data after server restart or initialization
// from shared storage in a distributed deployment.
//
// The state is cloned internally to prevent external modifications from affecting
// the storage state.
//
// Parameters:
//   - state: Complete certificate state to restore (must not be nil)
//
// Returns:
//   - nil on success
//   - error if state is nil
//
// Example - Restoring state on startup:
//
//	storage := webserver.NewStorage(callback)
//
//	// Load state from database
//	data, err := db.Query("SELECT state FROM webserver_state WHERE id = 1")
//	if err == nil {
//	    state := &webserverProto.State{}
//	    if err := proto.Unmarshal(data, state); err == nil {
//	        if err := storage.SetState(state); err != nil {
//	            log.Printf("Failed to restore state: %v", err)
//	        }
//	    }
//	}
func (s *Storage) SetState(state *webserverProto.State) error {
	if state == nil {
		return protoerrors.NewErrMissingInvalidData(nil, "state cannot be nil")
	}
	s.state = proto.Clone(state).(*webserverProto.State)
	return nil
}

// GetState returns a copy of the current certificate state.
//
// This method provides a snapshot of the current certificate state tree,
// which can be persisted to storage or inspected for debugging.
//
// The returned state is a deep copy, ensuring thread-safety and preventing
// external modifications from affecting the storage state.
//
// Returns:
//   - Deep copy of current state, or nil if no state has been set
//
// Example - Periodic state backup:
//
//	storage := webserver.NewStorage(callback)
//	ticker := time.NewTicker(5 * time.Minute)
//
//	go func() {
//	    for range ticker.C {
//	        if state := storage.GetState(); state != nil {
//	            data, _ := proto.Marshal(state)
//	            db.Exec("UPDATE webserver_state SET data = $1", data)
//	        }
//	    }
//	}()
func (s *Storage) GetState() *webserverProto.State {
	if s.state == nil {
		return nil
	}
	return proto.Clone(s.state).(*webserverProto.State)
}

// updateState updates the state timestamp and notifies the callback.
//
// This internal method is called after every mutation operation (Store, Delete)
// to persist the updated state to distributed storage.
//
// Returns error from UpdateWebServerState callback, if any.
func (s *Storage) updateState() error {
	s.state.LastUpdated = time.Now().Unix()
	return s.callback.UpdateWebServerState(s.state)
}

// Store implements certmagic.Storage.Store.
//
// Stores certificate data at the specified key in the state tree and
// synchronizes to distributed storage via UpdateWebServerState callback.
//
// This method is called by CertMagic to persist:
//   - Certificate files (*.crt)
//   - Private keys (*.key)
//   - ACME account data
//   - Certificate metadata
//
// The key follows a filesystem-like path structure (e.g., "acme/example.com/cert.pem").
// Parent directories are created automatically as needed.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - key: Path-like key for storage location
//   - value: Raw certificate data to store
//
// Returns:
//   - nil on success
//   - error if storage or callback fails
//
// Example key structures:
//   - "acme/example.com/example.com.crt" - Certificate file
//   - "acme/example.com/example.com.key" - Private key
//   - "acme/acme-v02.api.letsencrypt.org-directory/users/default/user.json" - ACME account
func (s *Storage) Store(_ context.Context, key string, value []byte) error {
	s.ensurePath(key, false)
	node := s.getNode(key)
	if node != nil {
		node.Value = value
		node.ModTime = time.Now().Unix()
		node.IsDir = false
		return s.updateState()
	}
	return protoerrors.NewErrGeneral(nil, "failed to store key: %s", key)
}

// Load implements certmagic.Storage.Load.
//
// Retrieves certificate data from the state tree at the specified key.
//
// This method is called by CertMagic to load certificate data, private keys,
// and ACME account information during certificate operations.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - key: Path-like key identifying the data to load
//
// Returns:
//   - Certificate data if found
//   - fs.ErrNotExist if key doesn't exist or points to a directory
//
// Example:
//
//	data, err := storage.Load(ctx, "acme/example.com/example.com.crt")
//	if err == fs.ErrNotExist {
//	    log.Println("Certificate not found")
//	} else if err != nil {
//	    log.Printf("Load failed: %v", err)
//	}
func (s *Storage) Load(_ context.Context, key string) ([]byte, error) {
	node := s.getNode(key)
	if node == nil || node.IsDir {
		return nil, fs.ErrNotExist
	}
	return node.Value, nil
}

// Delete implements certmagic.Storage.Delete.
//
// Removes certificate data at the specified key from the state tree and
// synchronizes to distributed storage via UpdateWebServerState callback.
//
// This method is called by CertMagic during certificate cleanup operations.
// It only removes the file entry; parent directories are preserved.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - key: Path-like key identifying the data to delete
//
// Returns:
//   - nil on success (even if key didn't exist)
//   - error if callback fails
//
// Example:
//
//	// Remove expired certificate
//	if err := storage.Delete(ctx, "acme/old.example.com/cert.pem"); err != nil {
//	    log.Printf("Delete failed: %v", err)
//	}
func (s *Storage) Delete(_ context.Context, key string) error {
	dir, file := path.Split(key)
	dir = strings.TrimSuffix(dir, "/")

	parent := s.getNode(dir)
	if parent != nil && parent.IsDir && parent.Certs != nil {
		delete(parent.Certs, file)
		return s.updateState()
	}
	return nil
}

// Exists implements certmagic.Storage.Exists.
//
// Checks whether certificate data exists at the specified key.
//
// This method returns true only for files (not directories) that exist
// in the state tree. It's used by CertMagic to check if certificates
// are already provisioned before requesting new ones.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - key: Path-like key to check
//
// Returns:
//   - true if key exists and points to a file
//   - false if key doesn't exist or points to a directory
//
// Example:
//
//	if storage.Exists(ctx, "acme/example.com/example.com.crt") {
//	    log.Println("Certificate already exists")
//	} else {
//	    log.Println("Need to provision certificate")
//	}
func (s *Storage) Exists(_ context.Context, key string) bool {
	node := s.getNode(key)
	return node != nil && !node.IsDir
}

// List implements certmagic.Storage.List.
//
// Lists all files under the specified prefix path, optionally recursing
// into subdirectories.
//
// This method is used by CertMagic to discover existing certificates,
// enumerate ACME accounts, and perform cleanup operations.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - prefix: Directory path to list (empty string lists from root)
//   - recursive: If true, includes files from all subdirectories
//
// Returns:
//   - Slice of file paths (relative to prefix)
//   - nil slice if prefix doesn't exist or contains no files
//   - error is always nil (interface requirement)
//
// Example:
//
//	// List all certificates for a domain
//	files, _ := storage.List(ctx, "acme/example.com", false)
//	for _, file := range files {
//	    log.Printf("Found: %s", file)
//	}
//
//	// Recursively list all ACME data
//	files, _ := storage.List(ctx, "acme", true)
func (s *Storage) List(_ context.Context, prefix string, recursive bool) ([]string, error) {
	prefix = strings.TrimPrefix(prefix, "/")
	node := s.getNode(prefix)
	if node == nil || !node.IsDir {
		return nil, nil
	}

	var results []string
	s.listRecursive(prefix, node, recursive, &results)
	return results, nil
}

// Stat implements certmagic.Storage.Stat.
//
// Retrieves metadata about a certificate file or directory in the state tree.
//
// This method returns information about modification time, size, and whether
// the key represents a terminal node (file) or directory. It's used by CertMagic
// for cache management and staleness checks.
//
// Parameters:
//   - ctx: Context (currently unused but required by interface)
//   - key: Path-like key to get metadata for
//
// Returns:
//   - KeyInfo with metadata if key exists
//   - fs.ErrNotExist if key doesn't exist
//
// Example:
//
//	info, err := storage.Stat(ctx, "acme/example.com/example.com.crt")
//	if err == nil {
//	    log.Printf("Certificate modified: %v", info.Modified)
//	    log.Printf("Certificate size: %d bytes", info.Size)
//	}
func (s *Storage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
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

// Lock implements certmagic.Storage.Lock.
//
// Acquires a distributed lock for the specified key, delegating to the
// Callback implementation.
//
// This method is called by CertMagic before certificate operations to ensure
// only one server instance performs ACME challenges at a time. This prevents
// Let's Encrypt rate limiting and ensures consistent certificate state.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - key: Unique identifier for the lock (typically domain name)
//
// Returns:
//   - nil if lock was successfully acquired
//   - error if lock is already held or acquisition failed
//
// Example:
//
//	// CertMagic calls this before certificate operations
//	if err := storage.Lock(ctx, "example.com"); err != nil {
//	    return fmt.Errorf("failed to acquire lock: %w", err)
//	}
//	defer storage.Unlock(ctx, "example.com")
func (s *Storage) Lock(ctx context.Context, key string) error {
	return s.callback.Lock(ctx, key)
}

// Unlock implements certmagic.Storage.Unlock.
//
// Releases a previously acquired distributed lock, delegating to the
// Callback implementation.
//
// This method is called by CertMagic after certificate operations complete,
// whether successful or not. It should always be called with defer to ensure
// locks are released even if operations fail.
//
// Parameters:
//   - ctx: Context for cancellation control
//   - key: Unique identifier for the lock (must match Lock call)
//
// Returns:
//   - nil if lock was successfully released
//   - error if unlock failed
//
// Example:
//
//	defer storage.Unlock(ctx, "example.com")
func (s *Storage) Unlock(ctx context.Context, key string) error {
	return s.callback.Unlock(ctx, key)
}

// getNode retrieves a node from the state tree by path.
//
// This internal method traverses the state tree following the path components
// in the key to locate the target node.
//
// Parameters:
//   - key: Path-like key (e.g., "acme/example.com/cert.pem")
//
// Returns:
//   - Node at the specified path, or nil if path doesn't exist
func (s *Storage) getNode(key string) *webserverProto.CertState {
	key = strings.TrimPrefix(key, "/")
	if key == "" || key == "." {
		return s.state.Cert
	}

	parts := strings.Split(key, "/")
	current := s.state.Cert

	for _, part := range parts {
		if part == "" {
			continue
		}
		if current == nil || !current.IsDir || current.Certs == nil {
			return nil
		}
		current = current.Certs[part]
	}

	return current
}

// ensurePath ensures all directories in the path exist.
//
// This internal method creates any missing directory nodes in the state tree
// needed to reach the target path. If isDir is false, also creates the final
// file node.
//
// Parameters:
//   - key: Path-like key (e.g., "acme/example.com/cert.pem")
//   - isDir: Whether the final path component should be a directory
func (s *Storage) ensurePath(key string, isDir bool) {
	key = strings.TrimPrefix(key, "/")
	parts := strings.Split(key, "/")

	// If this is a file, don't create the last part as a directory
	if !isDir && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}

	current := s.state.Cert
	if current.Certs == nil {
		current.Certs = make(map[string]*webserverProto.CertState)
	}

	for _, part := range parts {
		if part == "" {
			continue
		}
		if current.Certs[part] == nil {
			current.Certs[part] = &webserverProto.CertState{
				IsDir:   true,
				ModTime: time.Now().Unix(),
				Certs:   make(map[string]*webserverProto.CertState),
			}
		}
		current = current.Certs[part]
		if current.Certs == nil {
			current.Certs = make(map[string]*webserverProto.CertState)
		}
	}

	// Create the final node if it's a file
	if !isDir && len(strings.Split(key, "/")) > 0 {
		fileName := path.Base(key)
		parent := s.getNode(path.Dir(key))
		if parent != nil && parent.IsDir {
			if parent.Certs == nil {
				parent.Certs = make(map[string]*webserverProto.CertState)
			}
			if parent.Certs[fileName] == nil {
				parent.Certs[fileName] = &webserverProto.CertState{
					IsDir:   false,
					ModTime: time.Now().Unix(),
				}
			}
		}
	}
}

// listRecursive recursively lists all files under a node.
//
// This internal helper method traverses the state tree and collects file paths.
// Directories are skipped unless recursive is true.
//
// Parameters:
//   - prefix: Current path prefix
//   - node: Current node being traversed
//   - recursive: Whether to recurse into subdirectories
//   - results: Accumulator for file paths
func (s *Storage) listRecursive(prefix string, node *webserverProto.CertState, recursive bool, results *[]string) {
	if node == nil || !node.IsDir || node.Certs == nil {
		return
	}

	for name, child := range node.Certs {
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

// Ensure Storage implements certmagic.Storage interface
var _ certmagic.Storage = (*Storage)(nil)
