package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	letsencrypt "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/internal"
	"gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/s2sm"
	letsencrypt_pb "gitlab.com/secondstarcavalier/schematic/platform/services/letsencrypt/model/types/services/letsencrypt"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("letsencrypt: %v", err)
	}
}

func run() error {
	// Initialize the global zap logger so zap.L() calls in certmanager.go produce output.
	logger, err := zap.NewProduction()
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

	// letsencrypt builds the ServiceManager with New() but never calls its Run(),
	// because it drives its own CertManager lifecycle below. The SM sets the
	// health status to NOT_SERVING in New() and flips it to SERVING inside Run(),
	// so without this call the plaintext health listener on 8444 would stay
	// NOT_SERVING forever and k8s startup probes would fail indefinitely — the
	// same defect gateway hit ("service unhealthy (responded with NOT_SERVING)",
	// observed 114 times) and fixed the same way.
	//
	// SetServing drives the SAME handle that serves 8444. Do not substitute a
	// locally-created health reporter: that is a different health service from
	// the one k8s probes, and it silently does nothing.
	//
	// Placed here because bootstrap is complete — config, identity, state clients
	// and the cert manager are all constructed — and cm.Run is about to serve.
	s.SetServing(true)

	return cm.Run(ctx)
}

func resolveConfigPath() string {
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-c" || os.Args[i] == "--config" {
			return os.Args[i+1]
		}
	}
	return os.Getenv("SERVICE_CONFIG")
}
