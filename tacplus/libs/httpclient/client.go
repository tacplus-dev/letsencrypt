// Copyright (c) 2024 Second Star Cavalier, LLC.

// Package httpclient provides a typed HTTP client with retry logic.
// This package serves as the static library infrastructure for the compiler-generated typed HTTP client methods.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"

	httpclientProto "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/httpclient"
	"gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/libs/logger"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/errors"
	utils "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/utils"
)

// DefaultRetryConfig returns a default retry configuration
func defaultRetryConfig() *httpclientProto.RetryConfig {
	return &httpclientProto.RetryConfig{
		MaxRetries:           3,
		InitialBackoffMs:     100,
		MaxBackoffMs:         5000,
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []int32{429, 500, 502, 503, 504},
	}
}

// Client is an interface for HTTP clients that can be used by generated typed clients.
// This interface allows for easy testing and mocking of HTTP clients.
type Client interface {
	// HTTPClient returns the underlying HTTP client
	HTTPClient() *http.Client
	// RetryConfig returns the retry configuration for this client
	RetryConfig() *httpclientProto.RetryConfig
}

// TypedClient wraps the base HTTP client and provides type-safe methods with retry logic.
// Each method accepts full URLs, allowing the client to be reused for any endpoint.
// TypedClient implements the Client interface.
type TypedClient struct {
	client            *http.Client
	retryConfig       *httpclientProto.RetryConfig
	disableValidation bool
}

// NewTypedClient creates a new typed HTTP client from the provided HttpClientConfig.
// If config is nil, a default configuration is used.
// The retry configuration is taken from config.RetryConfig; if nil, DefaultRetryConfig() is used.
//
// Note: This client does not use a base URL. All methods accept full URLs as parameters,
// making the client reusable for any endpoint.
func NewTypedClient(config *httpclientProto.HttpClientConfig) (*TypedClient, error) {
	if config == nil {
		config = &httpclientProto.HttpClientConfig{}
	}

	retryConfig := config.RetryConfig
	if retryConfig == nil {
		retryConfig = defaultRetryConfig()
	}

	var errs *multierror.Error

	// Configure TLS
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Configure mTLS client certificate if provided
	if config.ClientCert != nil {
		zap.L().Debug("config.ClientCert is present; mTLS is enabled")

		// Decode the base64-encoded PEM key and cert
		keyPem, err := base64.URLEncoding.DecodeString(config.ClientCert.Key.Base64)
		if err != nil {
			errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to decode client key"))
		}
		certPem, err := base64.URLEncoding.DecodeString(config.ClientCert.Cert.Base64)
		if err != nil {
			errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to decode client certificate"))
		}

		// Create tls.Certificate from PEM bytes
		if err == nil {
			tlsCert, err := tls.X509KeyPair(certPem, keyPem)
			if err != nil {
				errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to load client certificate"))
			} else {
				tlsClientConfig.Certificates = []tls.Certificate{tlsCert}
			}
		}
	} else {
		zap.L().Debug("config.ClientCert is not present; mTLS is not enabled")
	}

	// Configure root CAs if provided
	lenRootCerts := len(config.RootCerts)
	if lenRootCerts > 0 {
		zap.L().Debug(fmt.Sprintf("config.RootCerts has %d cert(s)", lenRootCerts))

		certPool, err := x509.SystemCertPool()
		if err != nil {
			errs = multierror.Append(errs, protoerrors.NewErrGeneral(err, "failed to load system cert pool"))
		} else {
			for i, cert := range config.RootCerts {
				b, err := utils.DecodeBase64(cert.Base64)
				if err != nil {
					errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "failed to decode root cert %d", i))
					continue
				}

				if !certPool.AppendCertsFromPEM(b) {
					errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(nil, "failed to append root cert %d to pool", i))
				}
			}

			tlsClientConfig.RootCAs = certPool
		}
	} else {
		zap.L().Debug("config.RootCerts has no certs; using system default CAs")
	}

	if err := errs.ErrorOrNil(); err != nil {
		return nil, protoerrors.NewErrGeneral(err, "failed to configure TLS")
	}

	// Build HTTP transport with all settings
	transport := &http.Transport{
		TLSClientConfig:   tlsClientConfig,
		DisableKeepAlives: config.DisableKeepAlives,
	}

	// Apply connection pool settings
	if config.MaxIdleConns > 0 {
		transport.MaxIdleConns = int(config.MaxIdleConns)
		zap.L().Debug(fmt.Sprintf("MaxIdleConns set to %d", config.MaxIdleConns))
	}

	if config.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = int(config.MaxIdleConnsPerHost)
		zap.L().Debug(fmt.Sprintf("MaxIdleConnsPerHost set to %d", config.MaxIdleConnsPerHost))
	}

	// Apply timeout settings
	if config.IdleConnTimeoutSeconds > 0 {
		transport.IdleConnTimeout = time.Duration(config.IdleConnTimeoutSeconds) * time.Second
		zap.L().Debug(fmt.Sprintf("IdleConnTimeout set to %d seconds", config.IdleConnTimeoutSeconds))
	}

	if config.TlsHandshakeTimeoutSeconds > 0 {
		transport.TLSHandshakeTimeout = time.Duration(config.TlsHandshakeTimeoutSeconds) * time.Second
		zap.L().Debug(fmt.Sprintf("TLSHandshakeTimeout set to %d seconds", config.TlsHandshakeTimeoutSeconds))
	}

	if config.ExpectContinueTimeoutSeconds > 0 {
		transport.ExpectContinueTimeout = time.Duration(config.ExpectContinueTimeoutSeconds) * time.Second
		zap.L().Debug(fmt.Sprintf("ExpectContinueTimeout set to %d seconds", config.ExpectContinueTimeoutSeconds))
	}

	if config.ResponseHeaderTimeoutSeconds > 0 {
		transport.ResponseHeaderTimeout = time.Duration(config.ResponseHeaderTimeoutSeconds) * time.Second
		zap.L().Debug(fmt.Sprintf("ResponseHeaderTimeout set to %d seconds", config.ResponseHeaderTimeoutSeconds))
	}

	// Create HTTP client with configured transport
	httpClient := &http.Client{
		Transport: transport,
	}

	// Set overall request timeout
	if config.TimeoutSeconds > 0 {
		httpClient.Timeout = time.Duration(config.TimeoutSeconds) * time.Second
		zap.L().Debug(fmt.Sprintf("Client timeout set to %d seconds", config.TimeoutSeconds))
	}

	return &TypedClient{
		client:            httpClient,
		retryConfig:       retryConfig,
		disableValidation: config.DisableValidation,
	}, nil
}

// HTTPClient returns the underlying HTTP client
func (tc *TypedClient) HTTPClient() *http.Client {
	return tc.client
}

// RetryConfig returns the retry configuration for this client
func (tc *TypedClient) RetryConfig() *httpclientProto.RetryConfig {
	return tc.retryConfig
}

// DisableValidation returns whether validation is disabled for this client
func (tc *TypedClient) DisableValidation() bool {
	return tc.disableValidation
}

// DoGet performs a GET request with retry logic and deserializes using TypeFromBytes.
// This is a static helper function that can be called by generated code.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout
//   - client: The HTTP client to use
//   - url: The URL to request
//   - fromBytes: Function to deserialize response bytes into type T
//   - retryConfig: Retry configuration (if nil, no retries)
//
// Returns the deserialized response or an error from errors.proto
func DoGet[T any](
	ctx context.Context,
	client *http.Client,
	url string,
	fromBytes func([]byte) (*T, error),
	retryConfig *httpclientProto.RetryConfig,
) (*T, error) {
	var lastErr error
	maxAttempts := 1
	if retryConfig != nil && retryConfig.MaxRetries > 0 {
		maxAttempts = int(retryConfig.MaxRetries) + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate backoff and wait
			backoff := calculateBackoffDuration(retryConfig, attempt-1)
			zap.L().Debug(fmt.Sprintf("retrying GET %s, attempt %d/%d after %v", url, attempt+1, maxAttempts, backoff))
			select {
			case <-ctx.Done():
				return nil, protoerrors.NewErrCancelled("request cancelled during retry backoff")
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "failed to create request")
			continue
		}

		zap.L().Debug(fmt.Sprintf("GET %s (attempt %d/%d)", url, attempt+1, maxAttempts))

		resp, err := client.Do(req)
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "request failed")
			// Network errors are retryable
			if attempt < maxAttempts-1 {
				continue
			}
			break
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "failed to read response")
			continue
		}

		if logger.IsLogLevelTrace() {
			zap.L().Debug(fmt.Sprintf("GET %s -> %d, body=%s", url, resp.StatusCode, string(body)))
		} else {
			zap.L().Debug(fmt.Sprintf("GET %s -> %d", url, resp.StatusCode))
		}

		// Check for retryable status codes
		if resp.StatusCode >= 400 {
			shouldRetry := retryConfig != nil && isRetryableStatus(resp.StatusCode, retryConfig.RetryableStatusCodes)
			lastErr = statusCodeToError(resp.StatusCode)

			if shouldRetry && attempt < maxAttempts-1 {
				continue
			}
			return nil, lastErr
		}

		// Success - deserialize and return
		result, err := fromBytes(body)
		if err != nil {
			return nil, protoerrors.NewErrGeneral(err, "failed to deserialize response")
		}
		return result, nil
	}

	return nil, lastErr
}

// DoPostWithResponse performs POST with retry logic and deserializes the response using TypeFromBytes.
// This is a static helper function that can be called by generated code.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout
//   - client: The HTTP client to use
//   - url: The URL to request
//   - dataBytes: Pre-serialized request body bytes (from TypeToJSON)
//   - fromBytes: Function to deserialize response bytes into type T
//   - retryConfig: Retry configuration (if nil, no retries)
//
// Returns the deserialized response or an error from errors.proto
func DoPostWithResponse[T any](
	ctx context.Context,
	client *http.Client,
	url string,
	dataBytes []byte,
	fromBytes func([]byte) (*T, error),
	retryConfig *httpclientProto.RetryConfig,
) (*T, error) {

	var lastErr error
	maxAttempts := 1
	if retryConfig != nil && retryConfig.MaxRetries > 0 {
		maxAttempts = int(retryConfig.MaxRetries) + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := calculateBackoffDuration(retryConfig, attempt-1)
			zap.L().Debug(fmt.Sprintf("retrying POST %s, attempt %d/%d after %v", url, attempt+1, maxAttempts, backoff))
			select {
			case <-ctx.Done():
				return nil, protoerrors.NewErrCancelled("request cancelled during retry backoff")
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(dataBytes))
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "failed to create request")
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		if logger.IsLogLevelTrace() {
			zap.L().Debug(fmt.Sprintf("POST %s (attempt %d/%d), body=%s", url, attempt+1, maxAttempts, string(dataBytes)))
		} else {
			zap.L().Debug(fmt.Sprintf("POST %s (attempt %d/%d)", url, attempt+1, maxAttempts))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "request failed")
			// Network errors are retryable
			if attempt < maxAttempts-1 {
				continue
			}
			break
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "failed to read response")
			continue
		}

		if logger.IsLogLevelTrace() {
			zap.L().Debug(fmt.Sprintf("POST %s -> %d, body=%s", url, resp.StatusCode, string(body)))
		} else {
			zap.L().Debug(fmt.Sprintf("POST %s -> %d", url, resp.StatusCode))
		}

		// Check for retryable status codes
		if resp.StatusCode >= 400 {
			shouldRetry := retryConfig != nil && isRetryableStatus(resp.StatusCode, retryConfig.RetryableStatusCodes)
			lastErr = statusCodeToError(resp.StatusCode)

			if shouldRetry && attempt < maxAttempts-1 {
				continue
			}
			return nil, lastErr
		}

		// Success - deserialize and return
		result, err := fromBytes(body)
		if err != nil {
			return nil, protoerrors.NewErrGeneral(err, "failed to deserialize response")
		}
		return result, nil
	}

	return nil, lastErr
}

// DoMutation performs PUT/PATCH/DELETE with retry logic and typed data, returns no body.
// This is a static helper function that can be called by generated code.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout
//   - client: The HTTP client to use
//   - method: HTTP method (PUT, PATCH, DELETE)
//   - url: The URL to request
//   - dataBytes: Pre-serialized request body bytes (from TypeToJSON), can be nil
//   - retryConfig: Retry configuration (if nil, no retries)
//
// Returns an error from errors.proto if the request fails
func DoMutation(
	ctx context.Context,
	client *http.Client,
	method, url string,
	dataBytes []byte,
	retryConfig *httpclientProto.RetryConfig,
) error {

	var lastErr error
	maxAttempts := 1
	if retryConfig != nil && retryConfig.MaxRetries > 0 {
		maxAttempts = int(retryConfig.MaxRetries) + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := calculateBackoffDuration(retryConfig, attempt-1)
			zap.L().Debug(fmt.Sprintf("retrying %s %s, attempt %d/%d after %v", method, url, attempt+1, maxAttempts, backoff))
			select {
			case <-ctx.Done():
				return protoerrors.NewErrCancelled("request cancelled during retry backoff")
			case <-time.After(backoff):
			}
		}

		var bodyReader io.Reader
		if dataBytes != nil {
			bodyReader = bytes.NewReader(dataBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "failed to create request")
			continue
		}

		if dataBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		if logger.IsLogLevelTrace() && dataBytes != nil {
			zap.L().Debug(fmt.Sprintf("%s %s (attempt %d/%d), body=%s", method, url, attempt+1, maxAttempts, string(dataBytes)))
		} else {
			zap.L().Debug(fmt.Sprintf("%s %s (attempt %d/%d)", method, url, attempt+1, maxAttempts))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = protoerrors.NewErrGeneral(err, "request failed")
			// Network errors are retryable
			if attempt < maxAttempts-1 {
				continue
			}
			break
		}

		// Read body for logging
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = protoerrors.NewErrGeneral(readErr, "failed to read response")
			continue
		}

		if logger.IsLogLevelTrace() && len(body) > 0 {
			zap.L().Debug(fmt.Sprintf("%s %s -> %d, body=%s", method, url, resp.StatusCode, string(body)))
		} else {
			zap.L().Debug(fmt.Sprintf("%s %s -> %d", method, url, resp.StatusCode))
		}

		// Check for retryable status codes
		if resp.StatusCode >= 400 {
			shouldRetry := retryConfig != nil && isRetryableStatus(resp.StatusCode, retryConfig.RetryableStatusCodes)
			lastErr = statusCodeToError(resp.StatusCode)

			if shouldRetry && attempt < maxAttempts-1 {
				continue
			}
			return lastErr
		}

		// Success
		return nil
	}

	return lastErr
}

// Helper functions

// isRetryableStatus checks if a status code is in the retryable list
func isRetryableStatus(statusCode int, retryableCodes []int32) bool {
	// If no codes specified, use defaults
	if len(retryableCodes) == 0 {
		retryableCodes = []int32{429, 500, 502, 503, 504}
	}

	for _, code := range retryableCodes {
		if int(code) == statusCode {
			return true
		}
	}
	return false
}

// calculateBackoffDuration calculates the backoff duration for a retry attempt
func calculateBackoffDuration(config *httpclientProto.RetryConfig, attempt int) time.Duration {
	if config == nil {
		return 0
	}
	// Convert milliseconds to duration
	backoffMs := float64(config.InitialBackoffMs) * math.Pow(config.BackoffMultiplier, float64(attempt))
	if backoffMs > float64(config.MaxBackoffMs) {
		backoffMs = float64(config.MaxBackoffMs)
	}
	return time.Duration(backoffMs) * time.Millisecond
}

// statusCodeToError converts an HTTP status code to an appropriate BlueErr
func statusCodeToError(statusCode int) error {
	switch {
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return protoerrors.NewErrUnauthorized(nil, "HTTP %d: %s", statusCode, http.StatusText(statusCode))
	case statusCode == http.StatusNotFound:
		return protoerrors.NewErrNotFound("HTTP %d: %s", statusCode, http.StatusText(statusCode))
	case statusCode >= 400 && statusCode < 500:
		return protoerrors.NewErrMissingInvalidData(nil, "HTTP %d: %s", statusCode, http.StatusText(statusCode))
	default:
		return protoerrors.NewErrGeneral(nil, "HTTP %d: %s", statusCode, http.StatusText(statusCode))
	}
}
