// Copyright (c) 2024 Second Star Cavalier, LLC.

package webserver

import (
	"context"

	webserverProto "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/httpserver"
)

// Callback provides the interface for distributed certificate storage and locking.
//
// This interface must be implemented to use the webserver package, enabling
// certificate state persistence and distributed coordination across multiple
// server instances.
//
// # Purpose
//
// The Callback interface serves two critical functions:
//
//  1. Distributed Locking: Ensures only one server instance at a time can
//     obtain or renew Let's Encrypt certificates, preventing rate limit
//     violations and duplicate certificate requests.
//
//  2. State Persistence: Stores certificate data in a shared storage backend,
//     allowing certificate continuity across server restarts and sharing
//     certificates among multiple server instances.
//
// # Implementation Requirements
//
// Lock and Unlock methods must implement a distributed lock mechanism that:
//   - Prevents concurrent certificate operations across instances
//   - Handles lock timeouts appropriately
//   - Releases locks on context cancellation
//   - Supports lock names for different resources
//
// UpdateWebServerState must persist the state to shared storage that:
//   - Is accessible by all server instances
//   - Supports atomic updates to prevent corruption
//   - Provides reasonable durability guarantees
//   - Can handle frequent updates during certificate renewal
//
// # Example Implementation
//
// Example using Redis for locking and PostgreSQL for state:
//
//	type MyCallback struct {
//	    redis *redis.Client
//	    db    *sql.DB
//	}
//
//	func (c *MyCallback) Lock(ctx context.Context, name string) error {
//	    // Acquire distributed lock with 60 second timeout
//	    return c.redis.SetNX(ctx, "lock:"+name, "1", 60*time.Second).Err()
//	}
//
//	func (c *MyCallback) Unlock(ctx context.Context, name string) error {
//	    // Release distributed lock
//	    return c.redis.Del(ctx, "lock:"+name).Err()
//	}
//
//	func (c *MyCallback) UpdateWebServerState(state *proto.State) error {
//	    // Serialize state
//	    data, err := proto.Marshal(state)
//	    if err != nil {
//	        return err
//	    }
//	    // Store in database
//	    _, err = c.db.Exec("UPDATE webserver_state SET data = $1 WHERE id = 1", data)
//	    return err
//	}
//
// Example using etcd for both locking and storage:
//
//	type EtcdCallback struct {
//	    client *clientv3.Client
//	}
//
//	func (c *EtcdCallback) Lock(ctx context.Context, name string) error {
//	    session, err := concurrency.NewSession(c.client)
//	    if err != nil {
//	        return err
//	    }
//	    mutex := concurrency.NewMutex(session, "/locks/"+name)
//	    return mutex.Lock(ctx)
//	}
//
//	func (c *EtcdCallback) Unlock(ctx context.Context, name string) error {
//	    // Unlock implementation for etcd
//	    return nil
//	}
//
//	func (c *EtcdCallback) UpdateWebServerState(state *proto.State) error {
//	    data, err := proto.Marshal(state)
//	    if err != nil {
//	        return err
//	    }
//	    _, err = c.client.Put(context.Background(), "/webserver/state", string(data))
//	    return err
//	}
//
// # Lock Names
//
// The lock name parameter is typically a resource identifier such as:
//   - Domain name (e.g., "example.com")
//   - Certificate identifier
//   - Storage key path
//
// Ensure lock names are unique across different resources to prevent deadlocks.
//
// # Error Handling
//
// All methods should return descriptive errors that help diagnose issues:
//   - Lock conflicts (another instance holds the lock)
//   - Storage failures (network errors, disk full, etc.)
//   - Serialization errors
//   - Timeout errors
//
// # Thread Safety
//
// Implementations must be thread-safe as methods may be called concurrently
// from different goroutines within the webserver package.
//
// # Context Handling
//
// All methods receive a context parameter and should:
//   - Respect context cancellation
//   - Propagate context to downstream operations
//   - Return context.Canceled or context.DeadlineExceeded when appropriate
type Callback interface {
	// Lock acquires a distributed lock for the specified resource.
	//
	// This method is called before certificate operations to ensure only one
	// server instance performs ACME challenges and certificate provisioning
	// at a time. This prevents Let's Encrypt rate limiting and ensures
	// consistent certificate state.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - name: Unique identifier for the lock (typically domain name or resource ID)
	//
	// Returns:
	//   - nil if lock was successfully acquired
	//   - error if lock is already held, timeout occurred, or other failure
	//
	// The lock should be held until Unlock is called or context is cancelled.
	// Implementations should use appropriate timeout values (typically 30-60 seconds)
	// to prevent indefinite blocking.
	//
	// Example:
	//	if err := callback.Lock(ctx, "example.com"); err != nil {
	//	    return fmt.Errorf("failed to acquire lock: %w", err)
	//	}
	//	defer callback.Unlock(ctx, "example.com")
	Lock(ctx context.Context, name string) error

	// Unlock releases a previously acquired distributed lock.
	//
	// This method should be called after certificate operations complete,
	// whether successful or not. It's typically called with defer to ensure
	// locks are always released.
	//
	// Parameters:
	//   - ctx: Context for cancellation control
	//   - name: Unique identifier for the lock (must match Lock call)
	//
	// Returns:
	//   - nil if lock was successfully released
	//   - error if unlock failed (lock may have expired, or storage error)
	//
	// Note: If the lock has already expired or been released, implementations
	// should return nil rather than an error, as the desired state (unlocked)
	// has been achieved.
	//
	// Example:
	//	defer callback.Unlock(ctx, "example.com")
	Unlock(ctx context.Context, name string) error

	// UpdateWebServerState persists the current certificate state to shared storage.
	//
	// This method is called whenever certificate data changes, including:
	//   - New certificate provisioning
	//   - Certificate renewal
	//   - ACME account updates
	//   - Certificate metadata changes
	//
	// The state contains all certificate data, ACME account information, and
	// metadata needed to restore the server after restart or share certificates
	// across multiple instances.
	//
	// Parameters:
	//   - state: Complete certificate state to persist (will not be modified)
	//
	// Returns:
	//   - nil if state was successfully persisted
	//   - error if storage operation failed
	//
	// Implementations should:
	//   - Serialize state using protocol buffers (proto.Marshal)
	//   - Store in durable, shared storage (database, object storage, etc.)
	//   - Use atomic operations to prevent partial updates
	//   - Handle concurrent updates appropriately
	//   - Provide reasonable durability guarantees
	//
	// The state object contains sensitive data including certificate private keys.
	// Ensure appropriate security measures:
	//   - Encrypt state at rest
	//   - Use secure transport (TLS)
	//   - Implement proper access controls
	//   - Audit state access
	//
	// Example:
	//	func (c *MyCallback) UpdateWebServerState(state *proto.State) error {
	//	    data, err := proto.Marshal(state)
	//	    if err != nil {
	//	        return fmt.Errorf("failed to marshal state: %w", err)
	//	    }
	//
	//	    // Encrypt before storing
	//	    encrypted, err := c.encrypt(data)
	//	    if err != nil {
	//	        return fmt.Errorf("failed to encrypt state: %w", err)
	//	    }
	//
	//	    // Store in database
	//	    if err := c.db.SaveState(encrypted); err != nil {
	//	        return fmt.Errorf("failed to save state: %w", err)
	//	    }
	//
	//	    return nil
	//	}
	UpdateWebServerState(*webserverProto.State) error
}
