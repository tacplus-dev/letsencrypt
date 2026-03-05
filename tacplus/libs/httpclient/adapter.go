// Copyright (c) 2024 Second Star Cavalier, LLC.

package httpclient

import (
	"context"

	httpinterface "gitlab.com/secondstarcavalier/controlplane/services/interfaces/go/httpclient"
)

// Adapter implements the httpinterface.HTTPClient interface by wrapping a TypedClient.
// This adapter bridges the generic interface pattern used by generated code
// with the concrete TypedClient implementation, preventing circular dependencies.
//
// Type parameter T represents the proto message type being operated on.
type Adapter[T any] struct {
	client *TypedClient
}

// NewAdapter creates a new adapter that implements utils.HTTPClient[T].
//
// Parameters:
//   - client: A configured TypedClient with retry logic and TLS settings
//
// Returns an adapter that can be passed to any generated client constructor.
//
// Example:
//
//	baseClient, err := httpclient.NewTypedClient(config)
//	if err != nil {
//	    return err
//	}
//	adapter := httpclient.NewAdapter[logger.LoggerConfig](baseClient)
//	loggerClient := loggerconfig.NewTypedClient(adapter)
func NewAdapter[T any](client *TypedClient) httpinterface.HTTPClient[T] {
	return &Adapter[T]{client: client}
}

// DoGet performs a GET request with retry logic and deserializes the response.
func (a *Adapter[T]) DoGet(ctx context.Context, url string, fromBytes func([]byte) (*T, error)) (*T, error) {
	return DoGet(
		ctx,
		a.client.HTTPClient(),
		url,
		fromBytes,
		a.client.RetryConfig(),
	)
}

// DoPostWithResponse performs a POST request with retry logic and deserializes the response.
func (a *Adapter[T]) DoPostWithResponse(ctx context.Context, url string, dataBytes []byte, fromBytes func([]byte) (*T, error)) (*T, error) {
	return DoPostWithResponse(
		ctx,
		a.client.HTTPClient(),
		url,
		dataBytes,
		fromBytes,
		a.client.RetryConfig(),
	)
}

// DoMutation performs PUT/PATCH/DELETE requests with retry logic.
func (a *Adapter[T]) DoMutation(ctx context.Context, method, url string, dataBytes []byte) error {
	return DoMutation(
		ctx,
		a.client.HTTPClient(),
		method,
		url,
		dataBytes,
		a.client.RetryConfig(),
	)
}

// IsValidationDisabled returns whether validation is disabled for this client.
// The value comes from the HttpClientConfig.DisableValidation setting.
func (a *Adapter[T]) IsValidationDisabled() bool {
	return a.client.DisableValidation()
}
