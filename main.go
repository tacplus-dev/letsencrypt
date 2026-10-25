package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	letsencrypt "gitlab.com/seabeam/schematic/platform/services/letsencrypt/internal"
	loggerchassis "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/chassis/logger"
	"gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/chassis/servicemanager"
	"gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/s2sm"
	letsencrypt_fe "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/s2sm/grpc/servers/services/letsencrypt"
	letsencrypt_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	healthreport_pb "gitlab.com/seabeam/schematic/platform/services/letsencrypt/model/types/sys/healthreport"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("letsencrypt: %v", err)
	}
}

func run() error {
	// Initialize the global logger so zap.L() calls in certmanager.go produce output.
	//
	// Through the chassis, not straight from zap: the chassis wraps the sink in a
	// redactor, so a credential cannot reach the log through a structured FIELD.
	// This service holds the ACME account key and issues certificates, so its
	// error paths carry exactly the material that must never be logged. Same
	// bypass kmaker had, found by the same sweep — both are hand-written rather
	// than generated, which is how they missed the fleet-wide move to the chassis.
	logger, err := loggerchassis.InstallFromConfig(nil)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	zap.ReplaceGlobals(logger)
	defer logger.Sync() //nolint:errcheck

	configPath := resolveConfigPath()
	if configPath == "" {
		return fmt.Errorf("no config: use --config flag or set SERVICE_CONFIG env var")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config %s: %w", configPath, err)
	}

	cfg, err := letsencrypt_pb.ConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing letsencrypt config %s: %w", configPath, err)
	}

	s, err := sm.New()
	if err != nil {
		return fmt.Errorf("servicemanager: %w", err)
	}
	defer s.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	hostnames := cfg.GetHostnames()
	if len(hostnames) == 0 {
		return fmt.Errorf("letsencrypt config has no hostnames — set hostnames in config")
	}

	zap.L().Info("Starting letsencrypt", zap.Strings("hostnames", hostnames))

	cm, err := letsencrypt.NewCertManager(cfg, s, hostnames)
	if err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}

	// Run under the ServiceManager like every service: it serves the gRPC
	// listener with TLS (health included, which the launcher probes on 8443
	// and kills the child without), flips readiness to SERVING, and returns on
	// shutdown. The CertManager is this service's whole job, so it runs beside
	// it, started here and stopped by the handler's Shutdown; it dies loudly if
	// it fails, since a letsencrypt that is up but not managing certificates is
	// worse than one that restarts.
	h := &handler{stop: stop}
	go func() {
		if err := cm.Run(ctx); err != nil && ctx.Err() == nil {
			zap.L().Error("cert manager failed", zap.Error(err))
			s.Close()
			os.Exit(1)
		}
	}()
	return s.Run(h)
}

// handler is the generated Handler: this service hosts no RPC of its own
// (its state roots are kernel's), so it is health and shutdown.
type handler struct{ stop context.CancelFunc }

func (h *handler) LetsEncryptStateGrpcImpl() letsencrypt_fe.LetsEncryptStateServiceHandler {
	return notHostedState{}
}
func (h *handler) LetsEncryptStateConfig(*letsencrypt_pb.Config) error { return nil }
func (h *handler) LetsencryptConfigStateGrpcImpl() letsencrypt_fe.LetsencryptConfigStateServiceHandler {
	return notHostedConfigState{}
}
func (h *handler) LetsencryptConfigStateConfig(*letsencrypt_pb.Config) error { return nil }
func (h *handler) Shutdown(context.Context)                                  { h.stop() }
func (h *handler) CheckHealth() healthreport_pb.InstanceStatus {
	return healthreport_pb.InstanceStatus_INSTANCE_STATUS_HEALTHY
}
func (h *handler) RegisterAdditionalServices(grpc.ServiceRegistrar) {}

var errNotHosted = status.Error(codes.Unimplemented, "letsencrypt's state is served by the config store (kernel), not by letsencrypt")

type notHostedState struct{}

func (notHostedState) GetCertData(context.Context, *servicemanager.Caller) (*letsencrypt_pb.LetsEncryptCertData, error) {
	return nil, errNotHosted
}
func (notHostedState) SetCertData(context.Context, *servicemanager.Caller, *letsencrypt_pb.LetsEncryptCertData) (*letsencrypt_pb.LetsEncryptCertData, error) {
	return nil, errNotHosted
}
func (notHostedState) WatchCertData(*servicemanager.Caller, grpc.ServerStreamingServer[letsencrypt_pb.LetsEncryptCertData]) error {
	return errNotHosted
}

type notHostedConfigState struct{}

func (notHostedConfigState) GetConfig(context.Context, *servicemanager.Caller) (*letsencrypt_pb.Config, error) {
	return nil, errNotHosted
}
func (notHostedConfigState) SetConfig(context.Context, *servicemanager.Caller, *letsencrypt_pb.Config) (*letsencrypt_pb.Config, error) {
	return nil, errNotHosted
}
func (notHostedConfigState) WatchConfig(*servicemanager.Caller, grpc.ServerStreamingServer[letsencrypt_pb.Config]) error {
	return errNotHosted
}

func resolveConfigPath() string {
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-c" || os.Args[i] == "--config" {
			return os.Args[i+1]
		}
	}
	return os.Getenv("SERVICE_CONFIG")
}
