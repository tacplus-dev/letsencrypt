// Copyright (c) 2024 Second Star Cavalier, LLC.

package webserver

const (
	// DefaultHttpListen is the default address to listen on for HTTP connections.
	// This is the standard HTTP port.
	DefaultHttpListen = ":80"

	// DefaultHttpsListen is the default address to listen on for HTTPS connections.
	// This is the standard HTTPS port.
	DefaultHttpsListen = ":443"

	// DefaultEmailUser is the default username to use for the Let's Encrypt account email
	// address. The format is admin@<domain>, where domain is the FQDN of the server.
	// This is used when generating email addresses dynamically based on the domain.
	DefaultEmailUser = "admin"

	// DefaultLetsEncryptEmail is the default email address to use for Let's Encrypt
	// account registration and notifications. This email receives certificate expiration
	// warnings and important ACME account updates. This value is used when
	// Config.LetsEncryptEmail is not specified.
	DefaultLetsEncryptEmail = "admin@cavalier.io"
)
