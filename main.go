package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	genesis "gitlab.com/secondstarcavalier/controlplane/services/genesis/internal"
	"gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/libs/logger"
	"gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/libs/servicemanager"
	serviceconfig_pb "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/libs/serviceconfig"
	genesis_pb "gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/types/services/genesis"
	"gitlab.com/secondstarcavalier/controlplane/services/genesis/tacplus/wrappers/backends"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("genesis: %v", err)
	}
}

func run() error {
	// 1. Load serviceconfig.
	configPath := resolveConfigPath()
	if configPath == "" {
		return fmt.Errorf("no config: use --config flag or set SERVICE_CONFIG env var")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config %s: %w", configPath, err)
	}

	cfg, err := serviceconfig_pb.ConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing config %s: %w", configPath, err)
	}

	bsCfg, err := serviceconfig_pb.BootstrapConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing bootstrap config %s: %w", configPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// 2. Install logger.
	if cfg.Logger != nil {
		if _, err := logger.InstallFromConfig(cfg.Logger); err != nil {
			return fmt.Errorf("logger: %w", err)
		}
	}

	// 3. Parse typed config.
	genesisCfg, err := genesis_pb.ConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing genesis config %s: %w", configPath, err)
	}

	// 4. Connect to elvis via ServiceManager.
	sc, err := servicemanager.NewServiceManager(ctx, bsCfg)
	if err != nil {
		return fmt.Errorf("servicemanager: %w", err)
	}
	defer sc.Close()

	// 5. Create backend clients.
	bc, err := backends.NewBackends(ctx, sc)
	if err != nil {
		return fmt.Errorf("backends: %w", err)
	}
	defer bc.Close()

	// 6. Run the cert manager.
	zap.L().Info("Starting genesis", zap.String("fqdn", genesisCfg.Fqdn))

	cm, err := genesis.NewCertManager(genesisCfg, bc)
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
