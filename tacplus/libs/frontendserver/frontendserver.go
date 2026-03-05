// Copyright (c) 2024 Second Star Cavalier, LLC.
// Reusable frontendserver components
//
// This package provides a gRPC frontend server with TLS and graceful shutdown.
// Authorization is handled by the Authorizer (see authorizer.go), which is
// injected into the generated service wrapper by the service_manager.
//
// The BootstrapConfig comes from serviceconfig.proto (loaded from YAML at boot).
// Runtime configuration (OPA policy) is delivered via ServiceConfigState.
// REST, GraphQL, and static file serving are handled by a separate gateway.

package frontendserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	pb "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/serviceconfig"
	x509wrapper "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/libs/x509"
	"gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/libs/logger"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ServiceImplementation is the interface that generated server code must implement.
// It provides the method for registering gRPC services.
type ServiceImplementation interface {
	RegisterServices(grpcServer *grpc.Server) error
}

// FrontendServer manages the gRPC server lifecycle including TLS and graceful
// shutdown. Authorization is managed externally by the service_manager, which
// injects the authorizer into the generated wrapper before creating the server.
type FrontendServer struct {
	config *pb.Config
	impl   ServiceImplementation
	conn   grpc.ClientConnInterface
	ctx    context.Context
}

// New creates a new FrontendServer from a Config (runtime config from elvis).
// Authorization is managed externally — the caller sets up the authorizer and
// injects it into the wrapper before calling New.
//
// After creating the server, call Listen() to start it.
//
// Example:
//
//	wrapper := fe.NewIronMaidenService(svc)
//	wrapper.SetAuthorizeFunc(auth.Authorize)
//	srv, err := frontendserver.New(ctx, cfg, backendConn, wrapper)
//	if err != nil {
//	    return err
//	}
//	return srv.Listen(ctx)
func New(ctx context.Context, config *pb.Config, conn grpc.ClientConnInterface, impl ServiceImplementation) (*FrontendServer, error) {
	if impl == nil {
		return nil, protoerrors.NewErrMissingInvalidData(nil, "ServiceImplementation is required")
	}
	if config == nil {
		return nil, protoerrors.NewErrMissingInvalidData(nil, "config cannot be nil")
	}

	// Install logger from bootstrap config.
	if config.Logger != nil {
		if _, err := logger.InstallFromConfig(config.Logger); err != nil {
			zap.L().Error("Failed to install logger", zap.Error(err))
		}
	}

	return &FrontendServer{
		config: config,
		impl:   impl,
		conn:   conn,
		ctx:    ctx,
	}, nil
}

// Listen starts the gRPC server and blocks until the context is cancelled.
// If tls_cert is set in the config, the server uses TLS. Otherwise, it
// serves plaintext gRPC (suitable when TLS termination is handled upstream).
//
// The caller is responsible for signal handling (e.g., signal.NotifyContext).
func (ps *FrontendServer) Listen(ctx context.Context) error {
	listenAddr := ps.config.ListenAddress
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	var listener net.Listener
	var opts []grpc.ServerOption
	useTLS := ps.config.TlsCert != nil

	if useTLS {
		certPair, err := x509wrapper.NewImmutableX509CertPair(ps.config.TlsCert)
		if err != nil {
			return protoerrors.NewErrGeneral(err, "failed to load TLS certificate")
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*certPair.TlsCert()},
			NextProtos:   []string{"h2"},
			MinVersion:   tls.VersionTLS12,
		}

		lis, err := tls.Listen("tcp", listenAddr, tlsConfig)
		if err != nil {
			return protoerrors.NewErrGeneral(err, "failed to listen on %s", listenAddr)
		}
		listener = lis
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		lis, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return protoerrors.NewErrGeneral(err, "failed to listen on %s", listenAddr)
		}
		listener = lis
	}
	defer listener.Close()

	if ps.config.MaxRequestSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(int(ps.config.MaxRequestSize)))
	}

	grpcServer := grpc.NewServer(opts...)
	if err := ps.impl.RegisterServices(grpcServer); err != nil {
		return fmt.Errorf("failed to register services: %w", err)
	}

	zap.L().Info("gRPC server starting",
		zap.String("address", listenAddr),
		zap.Bool("tls", useTLS))

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		zap.L().Info("Shutting down gRPC server")
		grpcServer.GracefulStop()
	}()

	return grpcServer.Serve(listener)
}
