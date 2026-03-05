// Copyright (c) 2024 Second Star Cavalier, LLC.

package webserver

import (
	webserverProto "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/httpserver"
)


// ExampleConfig returns an example Config with default values for Let's Encrypt mode.
//
// This function provides a sample configuration that demonstrates the required
// settings for a Let's Encrypt-enabled web server. It's useful for testing,
// documentation, and as a starting point for custom configurations.
//
// The returned configuration includes:
//   - ServerMode: SERVER_MODE_LETS_ENCRYPT for automatic certificate provisioning
//   - HttpListen: ":80" for ACME HTTP-01 challenges
//   - HttpsListen: ":443" for secure connections
//   - FQDN: "host.example.com" (should be changed to your actual domain)
//   - // Notes: Descriptive comment about the configuration
//
// Returns:
//   - *proto.Config ready to use with webserver.New()
//
// Example - Using example config:
//
//	config := webserver.ExampleConfig()
//	config.Fqdn = "myserver.example.com"  // Change to your domain
//	config.LetsEncryptEmail = "admin@example.com"
//
//	server, err := webserver.New(config, callback)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example - Creating custom config:
//
//	config := webserver.ExampleConfig()
//	config.ServerMode = proto.ServerMode_SERVER_MODE_NO_TLS
//	config.HttpListen = ":8080"
//	config.Fqdn = ""  // Not needed for HTTP-only mode
//
// Note: The example FQDN "host.example.com" must be changed to your actual
// domain name before use in production. The domain must be publicly resolvable
// and point to the server for Let's Encrypt certificate provisioning to succeed.
func ExampleConfig() *webserverProto.Config {
	return &webserverProto.Config{
		// Notes:       "Example server configuration for Let's Encrypt mode",
		HttpListen:  DefaultHttpListen,
		HttpsListen: DefaultHttpsListen,
		Fqdn:        "host.example.com",
		ServerMode:  webserverProto.ServerMode_SERVER_MODE_LETS_ENCRYPT,
	}
}
