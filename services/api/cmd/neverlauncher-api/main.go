package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/eventbus"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/httpapi"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

var version = "dev"

func main() {
	cfg := config.Load()

	if err := config.ValidateProduction(cfg); err != nil {
		log.Fatal(err)
	}
	if err := httpapi.ValidatePersistenceConfig950(cfg); err != nil {
		log.Fatal(err)
	}
	repo := newRepository(cfg)
	if migrator, ok := repo.(interface {
		MigrationStatus(context.Context) (dbmigrate.Status, error)
		ApplyMigrations(context.Context) (dbmigrate.Status, error)
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if cfg.DatabaseAutoMigrate {
			status, err := migrator.ApplyMigrations(ctx)
			if err != nil {
				log.Fatalf("database migration failed: %v", err)
			}
			log.Printf("database schema ready migration=%s applied=%d/%d", status.Current, status.Applied, status.Total)
		} else {
			status, err := migrator.MigrationStatus(ctx)
			if err != nil {
				log.Fatalf("database migration status failed: %v", err)
			}
			if !status.Compatible || len(status.Pending) > 0 {
				log.Fatalf("database schema incompatible/pending: current=%s pending=%v", status.Current, status.Pending)
			}
		}
	}

	if strings.EqualFold(cfg.Environment, "production") || strings.EqualFold(cfg.Environment, "prod") {
		if err := httpapi.ValidateManifestSigningConfig(cfg.ManifestSigningPrivateKey); err != nil {
			log.Fatal(err)
		}
	}

	if err := httpapi.InitializeInstallationSecurityP0(cfg); err != nil {
		log.Fatal(err)
	}

	state := httpapi.NewRuntimeState()
	if err := state.ConfigureProductRuntime(cfg); err != nil {
		log.Fatal(err)
	}
	federationCtx, federationCancel := context.WithTimeout(context.Background(), 15*time.Second)
	federationCore, err := httpapi.NewFederationCore(federationCtx, repo, cfg)
	federationCancel()
	if err != nil {
		log.Fatalf("federation core initialization failed: %v", err)
	}
	defer federationCore.Close()
	if err := httpapi.ConfigureAuthCore111(cfg, state); err != nil {
		log.Fatal(err)
	}
	if err := httpapi.BootstrapPersistence950(cfg, state); err != nil {
		if strings.EqualFold(cfg.Environment, "production") || strings.EqualFold(cfg.Environment, "prod") {
			log.Fatal(err)
		}
		log.Printf("persistence bootstrap 0.10.0 пропущен: %v", err)
	}

	store, err := newStorage(cfg)
	if err != nil {
		log.Fatal(err)
	}

	var events *eventbus.Bus
	if cfg.ExtensionEventsEnabled {
		events, err = eventbus.New(eventbus.Config{
			WorkerInterval: time.Duration(cfg.ExtensionEventsWorkerIntervalMilliseconds) * time.Millisecond,
			LeaseDuration:  time.Duration(cfg.ExtensionEventsLeaseSeconds) * time.Second,
			HookTimeout:    time.Duration(cfg.ExtensionEventsHookTimeoutMilliseconds) * time.Millisecond,
			MaxAttempts:    cfg.ExtensionEventsMaxAttempts,
			BaseRetry:      time.Duration(cfg.ExtensionEventsBaseRetryMilliseconds) * time.Millisecond,
			MaxRetry:       time.Duration(cfg.ExtensionEventsMaxRetrySeconds) * time.Second,
			BatchSize:      cfg.ExtensionEventsBatchSize,
		}, repo)
		if err != nil {
			log.Fatalf("NeverExtensions event bus initialization failed: %v", err)
		}
		if sinkRepo, ok := repo.(interface{ SetAuditEventSink(func(model.AuditEvent)) }); ok {
			sinkRepo.SetAuditEventSink(func(a model.AuditEvent) {
				if err := events.AuditCreated(context.Background(), a); err != nil {
					log.Printf("NeverExtensions audit event publish failed: %v", err)
				}
			})
		}
	}

	var host *extensionhost.Supervisor
	if cfg.ExtensionHostEnabled {
		if err := extensionhost.HardenBackendProcess(); err != nil {
			log.Fatalf("extension host backend memory hardening failed: %v", err)
		}
		host = extensionhost.New(extensionhost.Config{
			ExtensionRoot:       cfg.ExtensionRoot,
			Listen:              cfg.ExtensionHostListen,
			StartupTimeout:      time.Duration(cfg.ExtensionHostStartupTimeoutSeconds) * time.Second,
			HeartbeatTimeout:    time.Duration(cfg.ExtensionHostHeartbeatTimeoutSeconds) * time.Second,
			StopTimeout:         time.Duration(cfg.ExtensionHostStopTimeoutSeconds) * time.Second,
			CapabilityTimeout:   time.Duration(cfg.ExtensionHostCapabilityTimeoutSeconds) * time.Second,
			MaxMemoryBytes:      cfg.ExtensionHostMaxMemoryMB << 20,
			MaxProcesses:        cfg.ExtensionHostMaxProcesses,
			MaxLogBytes:         cfg.ExtensionHostMaxLogBytes,
			MaxLogEntries:       cfg.ExtensionHostMaxLogEntries,
			MaxProtocolBody:     cfg.ExtensionHostMaxProtocolBodyBytes,
			MaxStorageReadBytes: cfg.ExtensionHostMaxStorageReadBytes,
			CrashLimit:          cfg.ExtensionHostCrashLimit,
			CrashWindow:         time.Duration(cfg.ExtensionHostCrashWindowSeconds) * time.Second,
			RestartBackoff:      time.Duration(cfg.ExtensionHostRestartBackoffMilliseconds) * time.Millisecond,
		}, repo, store)
		if events != nil {
			host.SetEventBus(events)
			events.SetDispatcher(host)
		}
		if err := host.Start(context.Background()); err != nil {
			log.Fatalf("extension host initialization failed: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = host.Close(ctx)
		}()
		for _, reconcileErr := range host.Reconcile(context.Background()) {
			log.Printf("extension host reconcile: %v", reconcileErr)
		}
		log.Printf("NeverExtensions Host protocol=%s isolation=%s", host.ProtocolURL(), host.ResourceIsolation())
	}

	if events != nil {
		events.Start(context.Background())
		defer events.Close()
		log.Printf("NeverExtensions Event Bus protocol=%s", eventbus.ProtocolVersion)
	}

	server := httpapi.Server{
		Version:       version,
		Config:        cfg,
		Repo:          repo,
		Storage:       store,
		State:         state,
		Federation:    federationCore,
		ExtensionHost: host,
		EventBus:      events,
	}

	log.Printf(
		"NeverLauncher API %s слушает %s repository=%s storage=%s environment=%s",
		version,
		cfg.HTTPAddr,
		cfg.RepositoryDriver+"("+cfg.SQLDriver+")",
		store.Driver(),
		cfg.Environment,
	)
	if err := http.ListenAndServe(cfg.HTTPAddr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

func newRepository(cfg config.Config) repository.Repository {
	switch strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver)) {
	case "", "memory", "inmemory", "in-memory":
		return repository.NewMemoryRepository(cfg.PublicURL)
	case "postgres", "postgresql", "sql":
		return repository.NewSQLRepository(cfg.SQLDriver, cfg.DatabaseDSN, cfg.PublicURL)
	default:
		log.Fatalf("неизвестный NEVERLAUNCHER_REPOSITORY_DRIVER=%q: fail-closed, memory fallback запрещён", cfg.RepositoryDriver)
		return nil
	}
}

func newStorage(cfg config.Config) (storage.Storage, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.StorageDriver)) {
	case "", "local":
		return storage.NewLocalStorage(cfg.StorageLocalPath), nil
	case "s3", "s3-compatible":
		store, err := storage.NewS3Storage(storage.S3Config{
			Endpoint:  cfg.StorageS3Endpoint,
			PublicURL: cfg.StorageS3PublicURL,
			Bucket:    cfg.StorageS3Bucket,
			Region:    cfg.StorageS3Region,
			AccessKey: cfg.StorageS3AccessKey,
			SecretKey: cfg.StorageS3SecretKey,
			PathStyle: cfg.StorageS3PathStyle,
		})
		if err != nil {
			return nil, fmt.Errorf("S3-хранилище не готово: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := store.Health(ctx); err != nil {
			return nil, fmt.Errorf("S3 health check не пройден: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("неизвестный NEVERLAUNCHER_STORAGE_DRIVER=%q", cfg.StorageDriver)
	}
}
