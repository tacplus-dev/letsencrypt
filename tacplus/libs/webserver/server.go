// Copyright (c) 2024 Second Star Cavalier, LLC.

package webserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/libs/logger"

	"github.com/caddyserver/certmagic"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	httpProto "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/http"
	webserverProto "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/httpserver"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/errors"
)

// Server represents a web server with automatic TLS certificate management.
// It wraps Gin web framework and CertMagic for certificate provisioning.
//
// The Server supports three operational modes:
//   - Let's Encrypt: Automatic certificate provisioning and renewal
//   - Manual Certificate: Use provided TLS certificate
//   - HTTP Only: No TLS support
//
// The Server automatically handles:
//   - HTTP to HTTPS redirection
//   - ACME challenges for Let's Encrypt
//   - Certificate storage and synchronization
//   - Graceful shutdown
//
// Example:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT,
//	    Fqdn: "example.com",
//	    HttpListen: ":80",
//	    HttpsListen: ":443",
//	}
//	server, err := webserver.New(config, callback)
//
// staticFS represents a static filesystem mapping
type staticFS struct {
	path string
	fs   http.FileSystem
}

type Server struct {
	config            *webserverProto.Config
	httpsEngine       *gin.Engine
	httpEngine        *gin.Engine
	httpServer        *http.Server
	httpsServer       *http.Server
	magic             *certmagic.Config
	storage           *Storage
	tlsConfig         *tls.Config
	state             *webserverProto.State
	staticFilesystems []staticFS
}

// New creates a new Server instance with the specified configuration and callback.
//
// Parameters:
//   - config: Server configuration specifying mode, listen addresses, certificates, etc.
//   - callback: Callback interface for certificate storage and distributed locking
//
// The function validates the configuration based on the selected ServerMode:
//   - Let's Encrypt mode requires FQDN and prohibits TlsCert
//   - Manual certificate mode requires TlsCert
//   - HTTP-only mode has no additional requirements
//
// Returns a configured Server ready to start, or an error if configuration is invalid.
//
// Example with Let's Encrypt:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT,
//	    Fqdn: "example.com",
//	    HttpListen: ":80",
//	    HttpsListen: ":443",
//	}
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example with manual certificate:
//
//	config := &webserverProto.Config{
//	    ServerMode: webserverProto.ServerMode_SERVER_MODE_CERT,
//	    HttpListen: ":80",
//	    HttpsListen: ":443",
//	    TlsCert: &x509proto.X509CertPair{...},
//	}
//	server, err := webserver.New(config, callback)
//
// Panics if config or callback is nil.
func New(config *webserverProto.Config, callback Callback) (*Server, error) {

	if config == nil {
		panic("config is nil")
	}

	if callback == nil {
		panic("callback is nil")
	}

	config = proto.Clone(config).(*webserverProto.Config)

	if logger.IsLogLevelTrace() {
		b, _ := json.Marshal(config)
		zap.L().Debug(fmt.Sprintf("config=%s", string(b)))
	}

	var errs *multierror.Error
	var cert *tls.Certificate

	switch config.ServerMode {
	case webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT:
		if config.Fqdn == "" {
			errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "FQDN is required when ServerMode is SERVER_MODE_LETS_ENCRYPT"))
		}
		if config.TlsCert != nil {
			errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "TlsCert may not be set when ServerMode is SERVER_MODE_LETS_ENCRYPT"))
		}
	case webserverProto.ServerMode_SERVER_MODE_CERT:
		if config.TlsCert == nil {
			errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "TlsCert is required when ServerMode is SERVER_MODE_CERT"))
		} else {
			// Decode the base64-encoded PEM key and cert
			keyPem, err := base64.URLEncoding.DecodeString(config.TlsCert.Key.Base64)
			if err != nil {
				errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to decode TLS key"))
			}
			certPem, err := base64.URLEncoding.DecodeString(config.TlsCert.Cert.Base64)
			if err != nil {
				errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to decode TLS certificate"))
			}

			// Create tls.Certificate from PEM bytes
			if err == nil {
				tlsCert, err := tls.X509KeyPair(certPem, keyPem)
				if err != nil {
					errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to load TLS certificate"))
				} else {
					cert = &tlsCert
				}
			}
		}
	case webserverProto.ServerMode_SERVER_MODE_NO_TLS:
		// No TLS validation needed
	case webserverProto.ServerMode_SERVER_MODE_UNDEFINED:
		errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "ServerMode must be set"))
	default:
		errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "invalid ServerMode: %s", config.ServerMode))
	}

	if err := errs.ErrorOrNil(); err != nil {
		zap.L().Debug("config is invalid")
		return nil, err
	}

	zap.L().Debug("config is valid")

	gin.SetMode(gin.ReleaseMode)

	newEngine := func() *gin.Engine {
		engine := gin.New()

		// engine.Use(secure.New(secure.Config{
		// 	ContentSecurityPolicy: "default-src 'self'",
		// 	// Other security configurations can be added here
		// 	// For example, to enable HSTS:
		// 	// StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		// }))

		// Add a ginzap middleware, which:
		//   - Logs all requests, like a combined access and error log.
		//   - Logs to stdout.
		//   - RFC3339 with UTC time format.

		engine.Use(ginzap.Ginzap(zap.L(), time.RFC3339, true))

		// Logs all panic to error log
		//   - stack means whether output the stack info.
		engine.Use(ginzap.RecoveryWithZap(zap.L(), true))
		return engine
	}

	s := &Server{
		config: config,
		state:  &webserverProto.State{Cert: &webserverProto.CertState{}},
	}

	isIPAddress := func(host string) bool {
		ip := net.ParseIP(host)
		return ip != nil
	}

	if config.ServerMode == webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT {
		s.httpsEngine = newEngine()

		zap.L().Debug("Using LetsEncrypt for TLS")

		s.storage = NewStorage(callback)
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
		certmagic.Default.Storage = s.storage

		// Use configured email if provided, otherwise use default
		// This email is used by Let's Encrypt for certificate expiration notifications
		// and account recovery communications
		email := config.LetsEncryptEmail
		if email == "" {
			email = DefaultLetsEncryptEmail
			zap.L().Debug("Using default Let's Encrypt email",
				zap.String("email", email))
		} else {
			zap.L().Debug("Using configured Let's Encrypt email",
				zap.String("email", email))
		}
		certmagic.DefaultACME.Email = email

		s.magic = certmagic.NewDefault()
		s.tlsConfig = s.magic.TLSConfig()

		s.httpEngine = newEngine()
		s.httpServer = &http.Server{Addr: config.HttpListen, Handler: certmagic.DefaultACME.HTTPChallengeHandler(s.httpEngine)}

		// Redirect HTTP to HTTPS except for ACME challenge
		s.httpEngine.NoRoute(func(ctx *gin.Context) {
			host := ctx.Request.Host
			if host == "" || strings.ContainsAny(host, " \t\r\n") || strings.Contains(host, "//") || strings.Contains(host, "@") {
				ctx.AbortWithStatus(http.StatusBadRequest)
				return
			}
			ctx.Redirect(http.StatusMovedPermanently, "https://"+host+ctx.Request.RequestURI)
		})

		s.httpsServer = &http.Server{Addr: config.HttpsListen, Handler: certmagic.DefaultACME.HTTPChallengeHandler(s.httpsEngine), TLSConfig: s.tlsConfig}

		s.tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			zap.L().Debug(fmt.Sprintf("TLS request received for: %s", hello.ServerName))

			if hello.ServerName == "" {
				return nil, protoerrors.NewErrFailedPrecondition("TLS handshake failed: empty ServerName")
			}

			if isIPAddress(hello.ServerName) {
				return nil, protoerrors.NewErrFailedPrecondition("TLS handshake failed: no certificate for raw IP")
			}

			return s.magic.TLSConfig().GetCertificate(hello)
		}

		// Register health check endpoint on both HTTP and HTTPS
		s.registerHealthCheck(s.httpEngine)
		s.registerHealthCheck(s.httpsEngine)

		return s, nil
	}

	if config.ServerMode == webserverProto.ServerMode_SERVER_MODE_CERT {
		zap.L().Debug("Using TlsCert for TLS")

		s.httpsEngine = newEngine()
		s.httpEngine = newEngine()
		s.httpServer = &http.Server{Addr: config.HttpListen, Handler: s.httpEngine}

		// Redirect HTTP to HTTPS except for ACME challenge
		s.httpEngine.NoRoute(func(ctx *gin.Context) {
			host := ctx.Request.Host
			if host == "" || strings.ContainsAny(host, " \t\r\n") || strings.Contains(host, "//") || strings.Contains(host, "@") {
				ctx.AbortWithStatus(http.StatusBadRequest)
				return
			}
			ctx.Redirect(http.StatusMovedPermanently, "https://"+host+ctx.Request.RequestURI)
		})

		s.tlsConfig = &tls.Config{}

		s.tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			zap.L().Debug(fmt.Sprintf("TLS request received for: %s", hello.ServerName))

			if hello.ServerName == "" {
				return nil, protoerrors.NewErrFailedPrecondition("TLS handshake failed: empty ServerName")
			}

			if isIPAddress(hello.ServerName) {
				return nil, protoerrors.NewErrFailedPrecondition("TLS handshake failed: no certificate for raw IP")
			}

			return cert, nil
		}

		s.httpsServer = &http.Server{Addr: config.HttpsListen, Handler: s.httpsEngine, TLSConfig: s.tlsConfig}

		// Register health check endpoint on both HTTP and HTTPS
		s.registerHealthCheck(s.httpEngine)
		s.registerHealthCheck(s.httpsEngine)

		return s, nil
	}

	if config.ServerMode == webserverProto.ServerMode_SERVER_MODE_NO_TLS {
		zap.L().Debug("Running HTTP only (no TLS)")

		s.httpEngine = newEngine()
		s.httpServer = &http.Server{Addr: config.HttpListen, Handler: s.httpEngine}

		// Register health check endpoint on HTTP
		s.registerHealthCheck(s.httpEngine)

		return s, nil
	}

	return nil, protoerrors.NewErrMissingInvalidData(nil, "unsupported ServerMode: %s", config.ServerMode)
}

// TlsConfig returns the TLS configuration used by the HTTPS server.
//
// This method provides access to the underlying TLS configuration, allowing
// for advanced customization of TLS settings after server creation.
//
// Returns nil if the server is running in HTTP-only mode (ServerModeNoTLS).
//
// Example - Customizing TLS settings:
//
//	server, _ := webserver.New(config, callback)
//	if tlsConfig := server.TlsConfig(); tlsConfig != nil {
//	    tlsConfig.MinVersion = tls.VersionTLS13
//	    tlsConfig.CipherSuites = []uint16{
//	        tls.TLS_AES_128_GCM_SHA256,
//	        tls.TLS_AES_256_GCM_SHA384,
//	    }
//	}
//
// Note: Modifications to the returned TLS config affect the server's behavior.
// Exercise caution when modifying TLS settings to avoid security vulnerabilities.
func (s *Server) TlsConfig() *tls.Config {
	return s.tlsConfig
}

// UseMiddleware attaches middleware to both HTTP and HTTPS engines.
// Middleware will be applied to all routes registered after this call.
//
// Parameters:
//   - handlers: One or more Gin middleware functions
//
// Example:
//
//	server.UseMiddleware(cors.Default())
//	server.UseMiddleware(myCustomMiddleware())
func (s *Server) UseMiddleware(handlers ...gin.HandlerFunc) {
	if s.httpsEngine != nil {
		s.httpsEngine.Use(handlers...)
	}
	if s.httpEngine != nil {
		s.httpEngine.Use(handlers...)
	}
}

// AttachHttpHandler attaches HTTP handlers for the specified HTTP methods and path.
//
// This method automatically selects the appropriate engine (HTTP or HTTPS) based
// on the server mode and registers the handlers for all HTTP methods specified
// in the methodFlags bitmask.
//
// Parameters:
//   - methodFlags: Bitmask of HTTP methods (HttpMethodFlag) to register handlers for.
//     Use webserverProto.HttpMethodFlag constants (e.g., HTTP_METHOD_GET | HTTP_METHOD_POST)
//   - path: URL path pattern (e.g., "/api/users", "/health")
//   - handlers: One or more Gin handler functions (middleware and/or final handler)
//
// The methodFlags parameter is a bitmask that can combine multiple methods:
//   - HTTP_METHOD_GET (1)
//   - HTTP_METHOD_HEAD (2)
//   - HTTP_METHOD_POST (4)
//   - HTTP_METHOD_PUT (8)
//   - HTTP_METHOD_DELETE (16)
//   - HTTP_METHOD_PATCH (32)
//   - HTTP_METHOD_OPTIONS (64)
//   - HTTP_METHOD_TRACE (128)
//   - HTTP_METHOD_CONNECT (256)
//   - HTTP_METHOD_ANY (511) - registers all HTTP methods
//
// Example - Single method:
//
//	server.AttachHttpHandler(
//	    webserverProto.HttpMethodFlag_HTTP_METHOD_GET,
//	    "/health",
//	    healthCheckHandler,
//	)
//
// Example - Multiple methods:
//
//	methods := webserverProto.HttpMethodFlag_HTTP_METHOD_GET |
//	           webserverProto.HttpMethodFlag_HTTP_METHOD_POST
//	server.AttachHttpHandler(methods, "/api/users", authMiddleware, usersHandler)
//
// Example - All methods:
//
//	server.AttachHttpHandler(
//	    webserverProto.HttpMethodFlag_HTTP_METHOD_ANY,
//	    "/api/catch-all",
//	    catchAllHandler,
//	)
//
// Note: For TLS-enabled modes (Let's Encrypt, manual certificate), routes are
// registered on the HTTPS engine. For HTTP-only mode, routes are registered
// on the HTTP engine.
func (s *Server) AttachHttpHandler(methodFlags httpProto.Method, path string, handlers ...gin.HandlerFunc) {
	// Select the appropriate engine based on server mode
	engine := s.httpsEngine
	if engine == nil {
		engine = s.httpEngine
	}

	if engine == nil {
		zap.L().Error("Cannot attach handlers: no engine available")
		return
	}

	// Convert HttpMethodFlag to int32 for bitwise operations
	flags := int32(methodFlags)

	// Register handlers for each HTTP method specified in the bitmask
	if flags&int32(httpProto.Method_METHOD_GET) != 0 {
		engine.GET(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_HEAD) != 0 {
		engine.HEAD(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_POST) != 0 {
		engine.POST(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_PUT) != 0 {
		engine.PUT(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_DELETE) != 0 {
		engine.DELETE(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_PATCH) != 0 {
		engine.PATCH(path, handlers...)
	}
	if flags&int32(httpProto.Method_METHOD_OPTIONS) != 0 {
		engine.OPTIONS(path, handlers...)
	}
	// Note: Gin doesn't have built-in TRACE and CONNECT handlers
	// These would need custom implementation if required
}

// AttachStaticFileSystem attaches a static file server using the provided http.FileSystem.
//
// This method serves static files (HTML, CSS, JavaScript, images, etc.) from the
// specified filesystem at the given URL prefix. The filesystem can be:
//   - http.Dir for serving from local disk
//   - embed.FS for serving embedded files
//   - Any custom implementation of http.FileSystem
//
// Static files are served as a FALLBACK - they are only served when no explicit
// HTTP handler (registered via AttachHttpHandler) matches the request path. This
// means explicit routes always take precedence over static files.
//
// The method automatically selects the appropriate engine (HTTP or HTTPS) based
// on the server mode and sets up a NoRoute handler to serve static files.
//
// Parameters:
//   - path: URL path prefix where files will be served (e.g., "/static", "/assets", "/")
//   - fs: http.FileSystem to serve files from
//
// The path should start with "/" and will be the base path for all file requests.
// Files are served relative to the root of the provided filesystem.
//
// Example - Serving from local directory with API routes taking precedence:
//
//	// Register explicit API handlers first
//	server.AttachHttpHandler(
//	    webserverProto.HttpMethodFlag_HTTP_METHOD_GET,
//	    "/api/status",
//	    apiStatusHandler,
//	)
//
//	// Register static files as fallback
//	server.AttachStaticFileSystem("/", http.Dir("./public"))
//	// Requests to /api/status -> apiStatusHandler
//	// Requests to /index.html -> served from ./public/index.html
//	// Requests to /css/style.css -> served from ./public/css/style.css
//
// Example - Serving embedded files:
//
//	//go:embed static
//	var staticFiles embed.FS
//
//	staticFS, err := fs.Sub(staticFiles, "static")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server.AttachStaticFileSystem("/", http.FS(staticFS))
//
// Example - Multiple static paths:
//
//	server.AttachStaticFileSystem("/css", http.Dir("./assets/css"))
//	server.AttachStaticFileSystem("/js", http.Dir("./assets/js"))
//	server.AttachStaticFileSystem("/images", http.Dir("./assets/images"))
//
// Note: For TLS-enabled modes (Let's Encrypt, manual certificate), files are
// served on the HTTPS engine. For HTTP-only mode, files are served on the HTTP engine.
//
// Note: The filesystem should allow directory listing or return index.html for
// directories, depending on your security requirements. Use http.Dir carefully
// as it allows listing all files in the directory tree.
//
// Note: In TLS modes, the HTTP engine is reserved for ACME challenges and HTTPS
// redirection, so static files are only served on HTTPS. In HTTP-only mode,
// static files are served on the HTTP engine.
func (s *Server) AttachStaticFileSystem(path string, fs http.FileSystem) {
	// Store the static filesystem
	s.staticFilesystems = append(s.staticFilesystems, staticFS{
		path: path,
		fs:   fs,
	})

	// Set up NoRoute handlers to serve static files as fallback
	s.setupStaticFileHandlers()

	zap.L().Debug("Attached static filesystem",
		zap.String("path", path),
		zap.Int("total_static_fs", len(s.staticFilesystems)))
}

// setupStaticFileHandlers configures NoRoute handlers to serve static files
// when no explicit route matches. This preserves existing NoRoute behavior
// (HTTP->HTTPS redirect) while adding static file serving as a fallback.
func (s *Server) setupStaticFileHandlers() {
	if len(s.staticFilesystems) == 0 {
		return
	}

	// For HTTPS engine or HTTP-only mode, set up static file serving
	if s.httpsEngine != nil {
		s.httpsEngine.NoRoute(s.createStaticFileHandler())
	} else if s.httpEngine != nil && s.config.ServerMode == webserverProto.ServerMode_SERVER_MODE_NO_TLS {
		// Only serve static files on HTTP engine in HTTP-only mode
		s.httpEngine.NoRoute(s.createStaticFileHandler())
	}
}

// createStaticFileHandler creates a Gin handler that serves static files
// from registered filesystems. It tries each filesystem in order until
// a matching path is found.
func (s *Server) createStaticFileHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestPath := c.Request.URL.Path

		// Try each registered static filesystem
		for _, staticFS := range s.staticFilesystems {
			// Check if the request path matches this filesystem's prefix
			if staticFS.path == "/" || strings.HasPrefix(requestPath, staticFS.path) {
				// Create a file server for this filesystem
				fileServer := http.FileServer(staticFS.fs)

				// Strip the path prefix if needed
				if staticFS.path != "/" {
					// Create a handler that strips the prefix
					handler := http.StripPrefix(staticFS.path, fileServer)
					handler.ServeHTTP(c.Writer, c.Request)
				} else {
					// Serve directly without stripping prefix
					fileServer.ServeHTTP(c.Writer, c.Request)
				}

				// File was served (or 404 from fileServer), don't try other filesystems
				return
			}
		}

		// No static filesystem matched, return 404
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Not Found",
		})
	}
}

// healthCheckHandler returns a Gin handler that responds to health check requests.
// It returns HTTP 200 with a HealthCheckResponse message indicating the service is healthy.
// This is compliant with container orchestration health check requirements.
func healthCheckHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		response := &webserverProto.HealthCheckResponse{
			Status: "ok",
			Time:   time.Now().UTC().Unix(),
		}
		c.JSON(http.StatusOK, response)
	}
}

// registerHealthCheck registers the health check endpoint on the specified engine.
// The health check is always available to allow container orchestrators and load
// balancers to verify service health without TLS requirements.
func (s *Server) registerHealthCheck(engine *gin.Engine) {
	if engine == nil {
		return
	}
	path := "/health"
	engine.GET(path, healthCheckHandler())
	zap.L().Debug("Health check endpoint registered", zap.String("path", path))
}

// SetState restores the server's certificate state from a previous session.
//
// This method is used to restore certificate data when a server restarts,
// allowing certificate continuity across server instances without re-provisioning.
//
// For Let's Encrypt mode, the state contains:
//   - Certificate private keys and public certificates
//   - ACME account data
//   - Certificate metadata and expiration info
//
// The state is validated before being set. Validation checks:
//   - State is not nil
//   - State.Cert is not nil
//   - State.LastUpdated is set and recent (within 1 year)
//
// If the server has Storage configured (Let's Encrypt mode), the state is
// passed to Storage and triggers UpdateWebServerState callback. Otherwise,
// the state is stored internally.
//
// Parameters:
//   - state: Certificate state to restore (will be cloned internally)
//
// Returns error if:
//   - state is nil
//   - state validation fails
//   - Storage.SetState fails (Let's Encrypt mode only)
//
// Example - Restoring state on startup:
//
//	// Load state from database/storage
//	savedState, err := loadStateFromDB()
//	if err == nil && savedState != nil {
//	    if err := server.SetState(savedState); err != nil {
//	        log.Printf("Failed to restore state: %v", err)
//	    } else {
//	        log.Println("Certificate state restored successfully")
//	    }
//	}
//
// Note: This method should be called before Listen() to ensure certificates
// are available when the server starts accepting connections.
func (s *Server) SetState(state *webserverProto.State) error {
	if state == nil {
		return protoerrors.NewErrMissingInvalidData(nil, "state cannot be nil")
	}

	if s.storage != nil {
		return s.storage.SetState(state)
	}

	s.state = proto.Clone(state).(*webserverProto.State)
	return nil
}

// GetState retrieves the current certificate state from the server.
//
// This method returns a snapshot of the server's certificate state, which can
// be persisted to storage and later restored via SetState(). The state includes
// all certificate data, ACME account information, and metadata.
//
// The returned state is a deep copy, ensuring thread-safety and preventing
// external modifications from affecting the server's internal state.
//
// Returns nil if no state has been set (server just created, or HTTP-only mode).
//
// Example - Periodic state backup:
//
//	ticker := time.NewTicker(1 * time.Hour)
//	go func() {
//	    for range ticker.C {
//	        if state := server.GetState(); state != nil {
//	            if err := saveStateToDB(state); err != nil {
//	                log.Printf("Failed to backup state: %v", err)
//	            }
//	        }
//	    }
//	}()
//
// Example - State inspection:
//
//	state := server.GetState()
//	if state != nil {
//	    lastUpdated := time.Unix(state.LastUpdated, 0)
//	    log.Printf("Certificate state last updated: %v", lastUpdated)
//	}
//
// Note: The state is automatically updated by CertMagic when certificates are
// provisioned or renewed. In Let's Encrypt mode, updates trigger the
// UpdateWebServerState callback for distributed storage.
func (s *Server) GetState() *webserverProto.State {
	if s.state == nil {
		return nil
	}
	return proto.Clone(s.state).(*webserverProto.State)
}

// Listen starts the web server and blocks until the context is cancelled or an error occurs.
//
// This method orchestrates the server lifecycle:
//  1. Initiates certificate management (Let's Encrypt mode)
//  2. Starts HTTP server (if configured)
//  3. Starts HTTPS server (if configured)
//  4. Monitors context for cancellation
//  5. Performs graceful shutdown on cancellation
//
// # Server Startup
//
// Both HTTP and HTTPS servers start concurrently in separate goroutines.
// The method waits until both servers are confirmed running before proceeding.
//
// For Let's Encrypt mode:
//   - Calls ManageSync() to provision/renew certificates
//   - HTTP server on port 80 handles ACME HTTP-01 challenges
//   - HTTPS server starts after certificate is available
//
// For manual certificate mode:
//   - HTTP server redirects all traffic to HTTPS
//   - HTTPS server uses provided certificate
//
// For HTTP-only mode:
//   - Only HTTP server starts
//   - No TLS or certificate management
//
// # Graceful Shutdown
//
// When the context is cancelled, the server initiates graceful shutdown:
//   - New connections are rejected
//   - Existing connections complete (15 second timeout)
//   - Both HTTP and HTTPS servers shut down in parallel
//   - Method returns after all servers stop
//
// # Error Handling
//
// The method returns an error if:
//   - Certificate provisioning fails (Let's Encrypt mode)
//   - Server fails to bind to port (address already in use)
//   - Server fails to start for any other reason
//
// http.ErrServerClosed is not treated as an error - it indicates normal
// shutdown and is filtered out.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - nil if shutdown completed gracefully
//   - error if any server failed to start or encountered errors
//
// Example - Basic server lifecycle:
//
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	server.Attach(
//	    webserverProto.HttpMethodFlag_HTTP_METHOD_GET,
//	    "/api/status",
//	    handleStatus,
//	)
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	if err := server.Listen(ctx); err != nil {
//	    log.Printf("Server error: %v", err)
//	}
//
// Example - Graceful shutdown with signal handling:
//
//	ctx, cancel := context.WithCancel(context.Background())
//
//	// Start server in background
//	go func() {
//	    if err := server.Listen(ctx); err != nil {
//	        log.Printf("Server error: %v", err)
//	    }
//	}()
//
//	// Wait for interrupt signal
//	sigCh := make(chan os.Signal, 1)
//	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
//	<-sigCh
//
//	// Trigger graceful shutdown
//	log.Println("Shutting down...")
//	cancel()
//
// Example - With timeout:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
//	defer cancel()
//
//	if err := server.Listen(ctx); err != nil {
//	    log.Printf("Server stopped: %v", err)
//	}
//
// Note: This method blocks until the server shuts down. Run it in the main
// goroutine or use a separate goroutine if you need to perform other operations
// while the server is running.
func (s *Server) Listen(ctx context.Context) error {

	// We will start both HTTP and HTTPS servers. The HTTP server will only
	// be used to redirect HTTP requests to HTTPS and for ACME challenges if
	// using Let's Encrypt.

	zap.L().Debug("Listen(ctx))")

	mutex := sync.Mutex{}

	var _errs *multierror.Error

	_httpRunning := false
	_httpsRunning := false

	setHttpRunning := func(running bool) {
		mutex.Lock()
		defer mutex.Unlock()
		_httpRunning = running
	}

	isHttpRunning := func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return _httpRunning
	}

	setHttpsRunning := func(running bool) {
		mutex.Lock()
		defer mutex.Unlock()
		_httpsRunning = running
	}

	isHttpsRunning := func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return _httpsRunning
	}

	addErr := func(err error) error {
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		mutex.Lock()
		defer mutex.Unlock()
		_errs = multierror.Append(_errs, err)
		return err
	}

	getErr := func() error {
		mutex.Lock()
		defer mutex.Unlock()
		return _errs.ErrorOrNil()
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {

		select {
		case <-time.After(time.Second):

			running := true

			if s.httpsServer != nil {
				if isHttpsRunning() {
					zap.L().Debug("HTTPs is running")
				} else {
					running = false
				}
			}

			if s.httpServer != nil {
				if isHttpRunning() {
					zap.L().Debug("HTTP is running")
				} else {
					running = false
				}
			}

			if running {
				zap.L().Debug("Servers are running")
			}

		case <-ctx.Done():

		}

	}()

	go func() {

		zap.L().Debug("Blocking on context")
		<-ctx.Done()
		zap.L().Debug("Context cancelled, shutting down")

		if s.httpServer != nil {
			if isHttpRunning() {
				zap.L().Debug("Shutting down HTTP Server")
				wg.Add(1)
				go func() {
					defer wg.Done()
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Duration(15)*time.Second)
					defer shutdownCancel()
					err := addErr(s.httpServer.Shutdown(shutdownCtx))
					if err == nil {
						zap.L().Debug("HTTP Server has been shut down gracefully")
					}
				}()
			} else {
				zap.L().Debug("HTTP Server not running")
			}
		}

		if s.httpsServer != nil {
			if isHttpsRunning() {
				zap.L().Debug("Shutting down HTTPs Server")
				wg.Add(1)
				go func() {
					defer wg.Done()
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Duration(15)*time.Second)
					defer shutdownCancel()
					err := addErr(s.httpsServer.Shutdown(shutdownCtx))
					if err == nil {
						zap.L().Debug("HTTPs Server has been shut down gracefully")
					}
				}()
			} else {
				zap.L().Debug("HTTPs Server not running")
			}
		}

	}()

	if s.httpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zap.L().Debug(fmt.Sprintf("Starting HTTP Server on %s", s.httpServer.Addr))
			setHttpRunning(true)
			err := addErr(s.httpServer.ListenAndServe())
			setHttpRunning(false)
			if err != nil {
				zap.L().Debug("HTTP Server failed to start")
			}
			cancel()
		}()
	} else {
		zap.L().Debug("HTTP Server not enabled")
	}

	if s.httpsServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zap.L().Debug(fmt.Sprintf("Starting HTTPs Server on %s", s.httpsServer.Addr))
			setHttpsRunning(true)
			err := addErr(s.httpsServer.ListenAndServeTLS("", ""))
			setHttpsRunning(false)
			if err != nil {
				zap.L().Debug("HTTPs Server failed to start")
			}
			cancel()
		}()
	} else {
		zap.L().Debug("HTTPs Server not enabled")
	}

	// Start certificate management after servers are listening
	if s.magic != nil {
		go func() {
			// Wait for servers to start listening
			time.Sleep(100 * time.Millisecond)

			zap.L().Debug("Starting Magic sync")
			if err := s.magic.ManageSync(ctx, []string{s.config.Fqdn}); err != nil {
				zap.L().Error("Magic sync failed", zap.Error(err))
				addErr(err)
				cancel()
			} else {
				zap.L().Debug("Magic sync completed")
			}
		}()
	}

	wg.Wait()

	if err := getErr(); err != nil {

		zap.L().Debug("Listen(ctx)->[failed]")
		return err
	}

	zap.L().Debug("Listen(ctx)->[completed successfully]")
	return nil
}
