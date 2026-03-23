package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	letsencrypt "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/internal"
	"gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/s2sm"
	letsencrypt_pb "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/services/letsencrypt"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("letsencrypt: %v", err)
	}
}

func run() error {
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

	fqdn := cfg.GetFqdn()
	if fqdn == "" {
		return fmt.Errorf("letsencrypt config has empty fqdn — set fqdn in config")
	}

	zap.L().Info("Starting letsencrypt", zap.String("fqdn", fqdn))

	cm, err := letsencrypt.NewCertManager(cfg, s, fqdn)
	if err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}

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
