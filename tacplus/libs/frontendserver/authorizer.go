// Copyright (c) 2024 Second Star Cavalier, LLC.

package frontendserver

import (
	"context"
	"fmt"
	"strings"
	"sync"

	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/errors"
	jwkviewpb "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/jwkview"
	wrapperJwk "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/libs/jwk"
	tokenlib "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/libs/token"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Authorizer performs authentication and authorization for service requests.
// Token signatures are verified against JWKs published by TokenExchanger.
// Authorization is deterministic: a valid token with matching aud grants access.
type Authorizer interface {
	Authorize(ctx context.Context, fullMethod string, req any) error
}

// jwkMap is a thread-safe map of kid -> ImmutableJwk, populated by watching
// the JwkVerifyingKeysViewService.
type jwkMap struct {
	mu      sync.RWMutex
	entries map[string]*wrapperJwk.ImmutableJwk
}

func (m *jwkMap) get(kid string) *wrapperJwk.ImmutableJwk {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries[kid]
}

func (m *jwkMap) watchView(ctx context.Context, client jwkviewpb.JwkVerifyingKeysViewServiceClient) {
	for {
		stream, err := client.Watch(ctx, &emptypb.Empty{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			zap.L().Error("Failed to watch JwkVerifyingKeysView", zap.Error(err))
			continue
		}

		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				zap.L().Warn("JwkVerifyingKeysView watch stream ended", zap.Error(err))
				break
			}

			newEntries := make(map[string]*wrapperJwk.ImmutableJwk, len(resp.Entries))
			for kid, proto := range resp.Entries {
				immutable, err := wrapperJwk.NewImmutableJwk(proto)
				if err != nil {
					zap.L().Warn("Skipping invalid JWK from view",
						zap.String("kid", kid),
						zap.Error(err))
					continue
				}
				newEntries[kid] = immutable
			}

			m.mu.Lock()
			m.entries = newEntries
			m.mu.Unlock()

			zap.L().Info("JWK view updated", zap.Int("count", len(newEntries)))
		}
	}
}

// authorizer implements the Authorizer interface using token signature verification.
// Authorization is deterministic: valid token with matching aud + entitlements = authorized.
type authorizer struct {
	jwks        *jwkMap
	serviceName string
}

// NewAuthorizer creates an Authorizer that verifies token signatures via JWK view.
// The conn parameter must be non-nil for JWK subscription.
// serviceName is the service_frontend annotation value (e.g. "fleetwood", "ironmaiden").
func NewAuthorizer(ctx context.Context, conn grpc.ClientConnInterface, serviceName string) (*authorizer, error) {
	jwks := &jwkMap{entries: make(map[string]*wrapperJwk.ImmutableJwk)}
	if conn != nil {
		viewClient := jwkviewpb.NewJwkVerifyingKeysViewServiceClient(conn)
		go jwks.watchView(ctx, viewClient)
	}

	zap.L().Info("Token-based authorization initialized",
		zap.Bool("token_verification", conn != nil),
		zap.String("service_name", serviceName))

	return &authorizer{
		jwks:        jwks,
		serviceName: serviceName,
	}, nil
}

// Authorize checks if the request is authorized by verifying the token signature,
// audience, and entitlements. Authorization is deterministic: a valid token with
// matching aud and an entitlement for the requested method grants access.
func (a *authorizer) Authorize(ctx context.Context, fullMethod string, req any) error {
	// Extract authorization header from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return protoerrors.NewErrUnauthorized(nil, "missing authorization header")
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 || authValues[0] == "" {
		return protoerrors.NewErrUnauthorized(nil, "missing authorization header")
	}

	tokenStr := authValues[0]
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = tokenStr[7:]
	}

	// Verify token signature and parse
	tw, err := a.verifyToken(tokenStr)
	if err != nil {
		zap.L().Debug("Token verification failed",
			zap.String("method", fullMethod),
			zap.Error(err))
		return protoerrors.NewErrUnauthorized(err, "token verification failed")
	}

	// Check aud matches service name
	if tw.GetAudience() != a.serviceName {
		return protoerrors.NewErrPermissionDenied(nil,
			"token audience %q does not match service %q", tw.GetAudience(), a.serviceName)
	}

	// Check entitlements contain the requested method
	methodName := extractMethodName(fullMethod)
	entitlements := tw.GetCustomField("entitlements")
	if entitlements == nil {
		return protoerrors.NewErrPermissionDenied(nil, "token missing entitlements claim")
	}
	entList, ok := entitlements.([]interface{})
	if !ok {
		return protoerrors.NewErrPermissionDenied(nil, "invalid entitlements format")
	}
	for _, e := range entList {
		if s, ok := e.(string); ok && (s == methodName || s == "*") {
			return nil
		}
	}
	return protoerrors.NewErrPermissionDenied(nil,
		"method %q not in entitlements for service %q", methodName, a.serviceName)
}

// verifyToken parses and verifies a JWT token string against the JWK view.
func (a *authorizer) verifyToken(tokenStr string) (*tokenlib.TokenWrapper, error) {
	tw, err := tokenlib.ParseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid := tw.GetKid()
	if kid == "" {
		return nil, fmt.Errorf("token missing key ID (kid) in header")
	}

	jwk := a.jwks.get(kid)
	if jwk == nil {
		return nil, fmt.Errorf("unknown signing key: %s", kid)
	}

	return tw, tw.Verify(jwk)
}

// extractMethodName returns the unqualified method name from a fully qualified gRPC method.
func extractMethodName(fullMethod string) string {
	if i := strings.LastIndex(fullMethod, "/"); i >= 0 {
		return fullMethod[i+1:]
	}
	return fullMethod
}
