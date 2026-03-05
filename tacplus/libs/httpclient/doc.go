// Copyright (c) 2024 Second Star Cavalier, LLC.

// Package httpclient provides a typed HTTP client with retry logic.
//
// This package serves as the static library infrastructure for compiler-generated typed HTTP client methods.
// The compiler generates type-safe client methods that call the generic helper functions provided by this package.
//
// # Architecture
//
// The package provides three main components:
//
// 1. TypedClient - A wrapper around http.Client with configured TLS, timeouts, and connection pooling
// 2. Static helper functions - Generic functions for GET, POST, and mutations with retry logic
// 3. RetryConfig - Configuration for exponential backoff retry behavior
//
// # Generated Code Pattern
//
// The compiler generates typed methods that use the static helper functions. For example,
// given a protobuf message type User, the compiler generates:
//
//	func (tc *TypedClient) GetUser(ctx context.Context, id string) (*User, error) {
//	    url := tc.baseURL + "/users/" + id
//	    return doGet(ctx, tc.client, url, UserFromBytes, tc.retryConfig)
//	}
//
//	func (tc *TypedClient) CreateUser(ctx context.Context, user *User) (*User, error) {
//	    url := tc.baseURL + "/users"
//	    data, err := UserToJSON(user)
//	    if err != nil {
//	        return nil, err
//	    }
//	    return doPostWithResponse(ctx, tc.client, url, data, UserFromBytes, tc.retryConfig)
//	}
//
//	func (tc *TypedClient) DeleteUser(ctx context.Context, id string) error {
//	    url := tc.baseURL + "/users/" + id
//	    return doMutation(ctx, tc.client, http.MethodDelete, url, nil, tc.retryConfig)
//	}
//
// # Retry Logic
//
// All HTTP operations support automatic retry with exponential backoff:
//   - Network errors are always retried
//   - HTTP status codes can be configured as retryable (default: 429, 500, 502, 503, 504)
//   - Backoff starts at 100ms and doubles each retry (configurable)
//   - Maximum backoff is capped at 5 seconds (configurable)
//   - Default maximum retries is 3 (configurable)
//
// # Debug and Trace Logging
//
// The library provides two levels of logging:
//
// Debug Level (always logged at debug):
//   - Request method, URL, attempt number, and status code
//
// Trace Level (only when the package-level function logger.IsLogLevelTrace() returns true):
//   - Request body (for POST/PUT/PATCH/DELETE)
//   - Response body
//
// Example debug logs (without trace):
//   - GET /users/123 (attempt 1/3)
//   - GET /users/123 -> 200
//   - POST /users (attempt 1/3)
//   - POST /users -> 201
//   - DELETE /users/123 (attempt 2/3)
//   - DELETE /users/123 -> 204
//
// Example trace logs (with trace enabled):
//   - GET /users/123 (attempt 1/3)
//   - GET /users/123 -> 200, body={"id":"123","name":"John"}
//   - POST /users (attempt 1/3), body={"name":"Jane"}
//   - POST /users -> 201, body={"id":"456","name":"Jane"}
//   - DELETE /users/123 (attempt 2/3)
//   - DELETE /users/123 -> 204
//
// # Error Handling
//
// All errors returned by this package are typed errors from the errors.proto schema:
//   - ErrNotFound (404)
//   - ErrUnauthorized (401, 403)
//   - ErrMissingInvalidData (400-499 client errors)
//   - ErrGeneral (500+ server errors, network errors)
//   - ErrCancelled (context cancellation)
//
// # Configuration
//
// The TypedClient is configured using HttpClientConfig from httpclient.proto, which supports:
//   - TLS configuration (InsecureSkipVerify, custom root CAs)
//   - mTLS client certificates
//   - Connection pooling (MaxIdleConns, MaxIdleConnsPerHost)
//   - Various timeouts (request, TLS handshake, idle connection, etc.)
//
// # Example Usage
//
//	// Create client with default retry config
//	config := &httpclientProto.HttpClientConfig{
//	    TimeoutSeconds: 30,
//	    MaxIdleConns: 100,
//	}
//	client, err := NewTypedClient("https://api.example.com", config, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use generated methods (compiler generates these)
//	user, err := client.GetUser(ctx, "user-123")
//	if err != nil {
//	    if errorsProto.IsErrNotFound(err) {
//	        // Handle not found
//	    }
//	    log.Fatal(err)
//	}
//
//	// Custom retry configuration
//	retryConfig := &RetryConfig{
//	    MaxRetries:           5,
//	    InitialBackoff:       200 * time.Millisecond,
//	    MaxBackoff:           10 * time.Second,
//	    BackoffMultiplier:    2.5,
//	    RetryableStatusCodes: []int{429, 503},
//	}
//	client, err = NewTypedClient("https://api.example.com", config, retryConfig)
package httpclient
