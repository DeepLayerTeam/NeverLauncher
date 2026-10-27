package main

import (
	"context"
	"encoding/json"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/trustbaseline"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/capacity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/deployment"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/eventbus"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionga"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/httpapi"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sentrydiag"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

var version = "dev"

// commit is injected by production builds using -ldflags; local builds report unknown.
var commit = "unknown"

func main() {
	// Read-only diagnostics work without a database, signing keys, TPM rights
	// or a running backend. They cannot produce a trusted attestation verdict.
	if len(os.Args) >= 3 && os.Args[1] == "diagnose" {
		switch os.Args[2] {
		case "device-trust":
			result := trustbaseline.DiagnoseHost()
			_ = json.NewEncoder(os.Stdout).Encode(result)
			if len(os.Args) == 4 && os.Args[3] == "--require-strict" {
				os.Exit(2)
			}
			return
		case "capacity":
			cfg := config.Load()
			plan, err := deployment.Detect(cfg)
			if err == nil {
				err = config.ValidateProduction(cfg)
			}
			if err != nil {
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": false, "error": err.Error()})
				os.Exit(2)
			}
			options := capacityOptions03215(cfg, string(plan.Mode))
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			report := capacity.Probe(ctx, options)
			cancel()
			_ = json.NewEncoder(os.Stdout).Encode(report)
			if !report.Verified {
				os.Exit(2)
			}
			for _, issue := range report.Issues {
				if issue.Severity == "critical" {
					os.Exit(2)
				}
			}
			return
		case "growth":
			cfg := config.Load()
			plan, err := deployment.Detect(cfg)
			if err == nil {
				err = config.ValidateProduction(cfg)
			}
			report := deployment.GrowthReport{Mode: plan.Mode}
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
				report, err = deployment.VerifyGrowth(ctx, cfg, plan)
				cancel()
			}
			result := struct {
				Checks   deployment.GrowthReport `json:"checks"`
				Verified bool                    `json:"verified"`
				Error    string                  `json:"error,omitempty"`
			}{Checks: report, Verified: err == nil}
			if err != nil {
				result.Error = err.Error()
			}
			_ = json.NewEncoder(os.Stdout).Encode(result)
			if err != nil {
				os.Exit(2)
			}
			return
		case "deployment":
			cfg := config.Load()
			plan, err := deployment.Detect(cfg)
			if err == nil {
				err = config.ValidateProduction(cfg)
			}
			result := struct {
				Topology           deployment.Plan `json:"topology"`
				ConfigurationValid bool            `json:"configurationValid"`
				Error              string          `json:"error,omitempty"`
			}{Topology: plan, ConfigurationValid: err == nil}
			if err != nil {
				result.Error = err.Error()
			}
			_ = json.NewEncoder(os.Stdout).Encode(result)
			if err != nil {
				os.Exit(2)
			}
			return
		case "extension-sandbox":
			result := extensionhost.DiagnoseIsolation0311()
			_ = json.NewEncoder(os.Stdout).Encode(result)
			if len(os.Args) == 4 && os.Args[3] == "--require-isolation" && !result.Enforced {
				os.Exit(2)
			}
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown diagnostic %q (expected deployment, device-trust or extension-sandbox; OS=%s)\n", os.Args[2], runtime.GOOS)
			os.Exit(2)
		}
	}
	cfg := config.Load()
	var diagnostics *sentrydiag.Reporter
	if sentrydiag.EnabledFromEnvironment() {
		if os.Getenv("NEVERLAUNCHER_SENTRY_BACKEND_DSN") == "" {
			log.Fatal("Sentry backend reporting enabled without DSN")
		}
		var err error
		diagnostics, err = sentrydiag.New(os.Getenv("NEVERLAUNCHER_SENTRY_BACKEND_DSN"), "neverlauncher@"+version+"+"+commit, cfg.Environment)
		if err != nil {
			log.Fatalf("invalid backend Sentry configuration: %v", err)
		}
	}
	defer diagnostics.Close()
	noExtensions := hasCommandArg02012(os.Args[1:], "--no-extensions")

	if err := config.ValidateProduction(cfg); err != nil {
		log.Fatal(err)
	}
	if err := httpapi.ValidatePersistenceConfig950(cfg); err != nil {
		log.Fatal(err)
	}
	// Lock the entire service BEFORE schema migration, installation bootstrap,
	// workers or an HTTP listener can mutate shared state. A second process
	// with a different SQLite coordinator path still conflicts on local storage.
	plan, err := deployment.Detect(cfg)
	if err != nil {
		log.Fatal(err)
	}
	owner, err := deployment.Acquire(plan)
	if err != nil {
		log.Fatalf("deployment owner lock: %v", err)
	}
	defer owner.Close()
	if plan.Mode == deployment.Standard || plan.Mode == deployment.NetworkHA {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		growth, probeErr := deployment.VerifyGrowth(ctx, cfg, plan)
		cancel()
		if probeErr != nil {
			log.Fatalf("deployment infrastructure preflight failed closed: %v", probeErr)
		}
		log.Printf("deployment infrastructure verified PostgreSQL=%t RedisLease=%t S3RoundTrip=%t", growth.PostgreSQL, growth.RedisLease, growth.S3RoundTrip)
	}
	log.Printf("deployment mode=%s repository=%s coordinator=%s storage=%s single_instance=%t reasons=%q", plan.Mode, plan.Repository, plan.Coordinator, plan.Storage, plan.SingleInstance, plan.Reasons)
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

	// Physically purge expired voluntary HWID risk observations and appeals.
	// Runs on all replicas; the idempotent repository operation is safe in HA.
	if janitor, ok := repo.(interface {
		PruneHWID0299(context.Context, time.Time) error
	}); ok {
		maintenanceCtx, stopHWID := context.WithCancel(context.Background())
		defer stopHWID()
		go func() {
			prune := func() {
				ctx, cancel := context.WithTimeout(maintenanceCtx, 20*time.Second)
				defer cancel()
				if err := janitor.PruneHWID0299(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
					log.Printf("HWID data retention cleanup failed: %v", err)
				}
			}
			prune()
			ticker := time.NewTicker(6 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-maintenanceCtx.Done():
					return
				case <-ticker.C:
					prune()
				}
			}
		}()
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
	lifecycle, err := httpapi.NewBackendLifecycle0289(os.Getenv("NEVERLAUNCHER_BACKEND_SUPERVISED_RESTART") == "true" && (strings.EqualFold(cfg.RepositoryDriver, "postgres") || strings.EqualFold(cfg.RepositoryDriver, "postgresql") || strings.EqualFold(cfg.RepositoryDriver, "sql")))
	if err != nil {
		log.Fatalf("backend instance identity: %v", err)
	}
	state.BackendLifecycle0289 = lifecycle
	if err := state.ConfigureProductRuntime(cfg); err != nil {
		log.Fatal(err)
	}
	defer state.CloseProductRuntime()
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

	capacityCollector := capacity.NewCollector(capacityOptions03215(cfg, string(plan.Mode)))
	capacityCtx, stopCapacity := context.WithCancel(context.Background())
	defer stopCapacity()
	go capacityCollector.Run(capacityCtx)

	secretKey, err := extensionsecurity.ParseKey(cfg.ExtensionSecretsKey)
	if err != nil {
		log.Fatalf("NeverExtensions secrets key: %v", err)
	}
	extSecurity, err := extensionsecurity.New(repo, secretKey)
	if err != nil {
		log.Fatalf("NeverExtensions capability security initialization failed: %v", err)
	}
	gaManager := extensionga.New(cfg.ExtensionRoot, cfg.ExtensionBackupRetention, repo, store)
	if !noExtensions {
		report, reconcileErr := gaManager.Reconcile(context.Background())
		if reconcileErr != nil {
			log.Fatalf("NeverExtensions GA reconciliation failed: %v", reconcileErr)
		}
		if len(report.Issues) > 0 {
			log.Printf("NeverExtensions GA reconciliation checked=%d healthy=%d disabled=%d issues=%d", report.Checked, report.Healthy, report.Disabled, len(report.Issues))
		}
	}

	var events *eventbus.Bus
	if cfg.ExtensionEventsEnabled && !noExtensions {
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
	if cfg.ExtensionHostEnabled && !noExtensions {
		if err := extensionhost.HardenBackendProcess(); err != nil {
			log.Fatalf("extension host backend memory hardening failed: %v", err)
		}
		host = extensionhost.New(extensionhost.Config{
			ExtensionRoot:        cfg.ExtensionRoot,
			Listen:               cfg.ExtensionHostListen,
			StartupTimeout:       time.Duration(cfg.ExtensionHostStartupTimeoutSeconds) * time.Second,
			HeartbeatTimeout:     time.Duration(cfg.ExtensionHostHeartbeatTimeoutSeconds) * time.Second,
			StopTimeout:          time.Duration(cfg.ExtensionHostStopTimeoutSeconds) * time.Second,
			CapabilityTimeout:    time.Duration(cfg.ExtensionHostCapabilityTimeoutSeconds) * time.Second,
			MaxMemoryBytes:       cfg.ExtensionHostMaxMemoryMB << 20,
			MaxProcesses:         cfg.ExtensionHostMaxProcesses,
			MaxLogBytes:          cfg.ExtensionHostMaxLogBytes,
			MaxLogEntries:        cfg.ExtensionHostMaxLogEntries,
			MaxProtocolBody:      cfg.ExtensionHostMaxProtocolBodyBytes,
			MaxStorageReadBytes:  cfg.ExtensionHostMaxStorageReadBytes,
			MaxHTTPRequestBytes:  cfg.ExtensionHTTPMaxRequestBytes,
			MaxHTTPResponseBytes: cfg.ExtensionHTTPMaxResponseBytes,
			HTTPTimeout:          time.Duration(cfg.ExtensionHTTPTimeoutSeconds) * time.Second,
			CrashLimit:           cfg.ExtensionHostCrashLimit,
			CrashWindow:          time.Duration(cfg.ExtensionHostCrashWindowSeconds) * time.Second,
			RestartBackoff:       time.Duration(cfg.ExtensionHostRestartBackoffMilliseconds) * time.Millisecond,
		}, repo, store)
		host.SetSecurity(extSecurity)
		lifecycle := extensionlifecycle.New(cfg.ExtensionRoot, cfg.ExtensionBackupRetention, repo, store)
		host.SetCrashLoopHandler(func(ctx context.Context, key extensionhost.Key, reason string) {
			if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: key.ExtensionID, Scope: key.Scope, ScopeID: key.ScopeID, Reason: reason, Source: "crash-loop"}); err != nil {
				log.Printf("extension crash-loop emergency-disable persistence failed %s: %v", key.ExtensionID, err)
				return
			}
			if _, err := lifecycle.Disable(ctx, key.ExtensionID, extensionlifecycle.Scope{Scope: key.Scope, ScopeID: key.ScopeID}); err != nil {
				log.Printf("extension crash-loop lifecycle disable failed %s: %v", key.ExtensionID, err)
			}
		})
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
		Capacity:          capacityCollector,
		Version:           version,
		SourceCommit:      commit,
		ExtensionSafeMode: noExtensions,
		Config:            cfg,
		Repo:              repo,
		Storage:           store,
		State:             state,
		Federation:        federationCore,
		ExtensionHost:     host,
		ExtensionSecurity: extSecurity,
		ExtensionGA:       gaManager,
		EventBus:          events,
	}

	durableCancel, durableErr := server.StartDurableControlPlane0213(context.Background())
	if durableErr != nil {
		log.Fatalf("durable control-plane initialization failed: %v", durableErr)
	}
	defer durableCancel()
	log.Printf("Durable control-plane active: publish jobs, fenced package leases and outbox recovery enabled")

	if noExtensions {
		log.Printf("NeverExtensions Safe Mode active: --no-extensions; extension host/event execution is disabled")
	}
	log.Printf(
		"NeverLauncher API %s слушает %s repository=%s storage=%s environment=%s",
		version,
		cfg.HTTPAddr,
		cfg.RepositoryDriver+"("+cfg.SQLDriver+")",
		store.Driver(),
		cfg.Environment,
	)
	// Own the HTTP server so a fenced restart request can drain open requests
	// without killing unrelated processes or using shell commands.
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		log.Fatal(err)
	}
	httpServer := &http.Server{Handler: diagnostics.Wrap(server.Handler()), ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(listener) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	select {
	case <-lifecycle.RestartRequested():
		log.Printf("supervised restart requested for instance %s; draining HTTP", lifecycle.InstanceID)
	case sig := <-stop:
		log.Printf("shutdown signal: %s", sig)
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v; closing open connections", err)
		_ = httpServer.Close()
	}
	// Exiting successfully is intentional. Only the externally configured service
	// manager should restart this process; the API does not spawn its own child.
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

func hasCommandArg02012(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}

// Only select configured local paths; the report never includes secrets or paths.
func capacityOptions03215(cfg config.Config, mode string) capacity.Options {
	opt := capacity.Options{Mode: mode, Driver: cfg.RepositoryDriver, DatabaseDSN: cfg.DatabaseDSN, CoordinatorPath: cfg.SQLiteCoordinatorPath, BackupPath: cfg.BackupRoot}
	if strings.EqualFold(cfg.StorageDriver, "local") || cfg.StorageDriver == "" {
		opt.StoragePath = cfg.StorageLocalPath
	}
	return opt
}
