// Copyright (c) 2024 Second Star Cavalier, LLC.

// Package webserver provides a high-level web server implementation with automatic TLS certificate management.
//
// This package wraps the Gin web framework and CertMagic library to provide:
//   - Automatic Let's Encrypt certificate provisioning
//   - Manual TLS certificate configuration
//   - HTTP-only mode (no TLS)
//   - Automatic HTTP to HTTPS redirection
//   - Distributed certificate storage via callbacks
//   - Graceful shutdown
//
// # Key Features
//
//   - Three server modes: Let's Encrypt, manual TLS certificate, or HTTP-only
//   - Automatic certificate renewal with Let's Encrypt
//   - Distributed certificate state sharing via callback interface
//   - Built on Gin framework for high-performance routing
//   - Structured logging with zap integration
//   - Graceful shutdown with context cancellation
//
// # Server Modes
//
// The package supports three TLS configuration modes:
//
//  1. SERVER_MODE_LETS_ENCRYPT: Automatic certificate provisioning via Let's Encrypt
//     - Requires FQDN (fully qualified domain name)
//     - Automatically handles ACME challenges
//     - Certificates stored in distributed state
//     - Auto-renewal before expiration
//
//  2. SERVER_MODE_CERT: Manual TLS certificate configuration
//     - Requires TLS certificate and key
//     - Full control over certificate management
//     - HTTP redirects to HTTPS
//
//  3. SERVER_MODE_NO_TLS: HTTP-only mode
//     - No TLS/HTTPS support
//     - Suitable for development or behind reverse proxy
//
// # Basic Usage - Let's Encrypt Mode
//
// Configure and start a server with automatic Let's Encrypt certificates:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT,
//	    FQDN: "example.com",
//	    HttpListen: ":80",     // Required for ACME challenges
//	    HttpsListen: ":443",
//	}
//
//	callback := &MyCallback{} // Implement webserver.Callback interface
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Configure routes
//	server.Engine().GET("/health", func(c *gin.Context) {
//	    c.JSON(200, gin.H{"status": "ok"})
//	})
//
//	// Start server with context for graceful shutdown
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	if err := server.Listen(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Basic Usage - Manual Certificate Mode
//
// Configure a server with manual TLS certificate:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_CERT,
//	    HttpListen: ":80",
//	    HttpsListen: ":443",
//	    TlsCert: &x509proto.X509CertPair{
//	        Certificate: &x509proto.X509Cert{Base64: certBase64},
//	        Key: &keyproto.Key{Base64: keyBase64},
//	    },
//	}
//
//	callback := &MyCallback{}
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	server.Engine().GET("/", handleRoot)
//
//	ctx := context.Background()
//	if err := server.Listen(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Basic Usage - HTTP Only Mode
//
// Configure a server without TLS (HTTP only):
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_NO_TLS,
//	    HttpListen: ":8080",
//	}
//
//	callback := &MyCallback{}
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	server.Engine().GET("/api/status", handleStatus)
//
//	ctx := context.Background()
//	if err := server.Listen(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Callback Interface
//
// The Callback interface must be implemented to provide certificate storage:
//
//	type MyCallback struct {
//	    storage CertificateStorage
//	}
//
//	func (c *MyCallback) Lock(ctx context.Context, name string) error {
//	    return c.storage.AcquireLock(ctx, name)
//	}
//
//	func (c *MyCallback) Unlock(ctx context.Context, name string) error {
//	    return c.storage.ReleaseLock(ctx, name)
//	}
//
//	func (c *MyCallback) UpdateWebServerState(state *webserverProto.State) error {
//	    return c.storage.Save(state)
//	}
//
// The Lock/Unlock methods ensure only one server instance at a time can obtain certificates.
// The UpdateWebServerState method persists certificate state for sharing across instances.
//
// # Graceful Shutdown
//
// The server supports graceful shutdown via context cancellation:
//
//	ctx, cancel := context.WithCancel(context.Background())
//
//	// Start server in goroutine
//	go func() {
//	    if err := server.Listen(ctx); err != nil {
//	        log.Printf("Server error: %v", err)
//	    }
//	}()
//
//	// Wait for signal
//	sigCh := make(chan os.Signal, 1)
//	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
//	<-sigCh
//
//	// Trigger graceful shutdown
//	cancel()
//
//	// Server will shutdown gracefully with 15 second timeout
//
// # State Management
//
// The server maintains certificate state that can be saved and restored:
//
//	// Get current state
//	state := server.GetState()
//
//	// Save state to storage
//	if err := storage.Save(state); err != nil {
//	    log.Printf("Failed to save state: %v", err)
//	}
//
//	// Restore state on startup
//	state, err := storage.Load()
//	if err == nil {
//	    if err := server.SetState(state); err != nil {
//	        log.Printf("Failed to restore state: %v", err)
//	    }
//	}
//
// # TLS Configuration
//
// Access TLS configuration for advanced use cases:
//
//	tlsConfig := server.TlsConfig()
//	if tlsConfig != nil {
//	    // Customize TLS settings
//	    tlsConfig.MinVersion = tls.VersionTLS13
//	}
//
// # Engine Access
//
// The server provides access to Gin engines for route configuration:
//
//	// Get the appropriate engine based on server mode
//	engine := server.Engine()  // Returns HTTPS engine if available, otherwise HTTP
//
//	// Access specific engines
//	httpEngine := server.HttpEngine()
//	httpsEngine := server.HttpsEngine()
//
//	// Configure routes
//	engine.GET("/api/users", handleUsers)
//	engine.POST("/api/users", createUser)
//	engine.PUT("/api/users/:id", updateUser)
//	engine.DELETE("/api/users/:id", deleteUser)
//
// # Middleware
//
// The server automatically includes:
//   - Zap logging middleware (access and error logs)
//   - Panic recovery middleware
//
// Add custom middleware:
//
//	engine := server.Engine()
//	engine.Use(myAuthMiddleware())
//	engine.Use(myCORSMiddleware())
//
// # Let's Encrypt Details
//
// When using SERVER_MODE_LETS_ENCRYPT:
//   - HTTP server runs on port 80 for ACME challenges
//   - HTTPS server runs on configured port (typically 443)
//   - HTTP automatically redirects to HTTPS (except ACME challenges)
//   - Certificates automatically renewed before expiration
//   - Certificate data stored via callback interface
//   - Email: admin@<your-domain> used for Let's Encrypt account
//
// # Error Handling
//
// The package returns errors in several scenarios:
//
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    // Configuration errors:
//	    // - Missing required fields (FQDN for Let's Encrypt, TlsCert for manual mode)
//	    // - Invalid TLS certificate
//	    // - Invalid server mode
//	    log.Fatalf("Failed to create server: %v", err)
//	}
//
//	if err := server.Listen(ctx); err != nil {
//	    // Runtime errors:
//	    // - Port already in use
//	    // - TLS handshake failures
//	    // - Certificate provisioning failures
//	    log.Printf("Server error: %v", err)
//	}
//
// # Best Practices
//
//  1. Always use Let's Encrypt in production for public-facing servers
//  2. Implement robust state persistence in your Callback
//  3. Use distributed locking to prevent multiple certificate requests
//  4. Handle graceful shutdown properly to avoid connection drops
//  5. Monitor certificate expiration and renewal
//  6. Use HTTPS-only mode for production deployments
//  7. Configure appropriate timeouts for your use case
//  8. Enable structured logging for debugging
//  9. Test certificate renewal before production deployment
//  10. Keep state backups in case of storage failures
//
// # Configuration
//
// The Config message supports the following fields:
//   - HttpListen: HTTP listen address (default ":80")
//   - HttpsListen: HTTPS listen address (default ":443")
//   - ServerMode: TLS configuration mode (required)
//   - FQDN: Fully qualified domain name (required for Let's Encrypt)
//   - TlsCert: TLS certificate pair (required for manual cert mode)
//
// # State Structure
//
// The State message contains:
//   - LastUpdated: Unix timestamp of last update
//   - Cert: Recursive tree structure of certificate data
//
// Certificate state mirrors the file system structure of Let's Encrypt data:
//   - Directories have IsDir=true and contain child entries in Certs map
//   - Files have IsDir=false and contain certificate data in Value
//   - ModTime tracks modification timestamps
//
// # Production Deployment
//
// For production deployment:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT,
//	    FQDN: os.Getenv("DOMAIN"),
//	    HttpListen: ":80",
//	    HttpsListen: ":443",
//	}
//
//	callback := &ProductionCallback{
//	    db: database,
//	    cache: redis,
//	}
//
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatalf("Server creation failed: %v", err)
//	}
//
//	// Configure routes
//	configureRoutes(server.Engine())
//
//	// Graceful shutdown
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	go func() {
//	    sigCh := make(chan os.Signal, 1)
//	    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
//	    <-sigCh
//	    cancel()
//	}()
//
//	if err := server.Listen(ctx); err != nil {
//	    log.Printf("Server shutdown: %v", err)
//	}
//
// # Security Considerations
//
//   - TLS 1.2+ is enforced by default
//   - Raw IP addresses are rejected for TLS handshakes
//   - Empty SNI (Server Name Indication) is rejected
//   - Let's Encrypt rate limits apply (50 certs per domain per week)
//   - Certificate private keys are stored in State - protect carefully
//   - Implement proper access controls on state storage
//   - Use TLS for internal communication in distributed deployments
//
// # Performance
//
//   - Gin provides high-performance routing
//   - HTTP/2 automatically enabled with TLS
//   - Connection keep-alive enabled by default
//   - Concurrent request handling
//   - Minimal memory footprint for certificate storage
//   - Efficient state serialization with protocol buffers
//
// # Troubleshooting
//
// Common issues and solutions:
//
//  1. "Port already in use" - Another process is using port 80 or 443
//     Solution: Stop conflicting process or change listen ports
//
//  2. "TLS handshake failed: empty ServerName" - Client didn't send SNI
//     Solution: Ensure clients properly set SNI in TLS config
//
//  3. "no certificate for raw IP" - Client connecting via IP address
//     Solution: Use domain name or implement custom certificate logic
//
//  4. Let's Encrypt certificate provisioning fails
//     Solution: Ensure DNS points to server and port 80 is accessible
//
//  5. State validation failures
//     Solution: Check state LastUpdated is recent and Cert structure is valid
//
// # Related Packages
//
//   - gitlab.com/secondstarcavalier/cloud/tacd3a/types/common/webserver - Protocol buffer types
//   - github.com/gin-gonic/gin - Web framework
//   - github.com/caddyserver/certmagic - Certificate management
//
// For more information, see the examples directory and individual function documentation.
package webserver
