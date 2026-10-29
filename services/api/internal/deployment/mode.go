// Package deployment selects and enforces the actual, supported API topology.
// It never turns an unavailable durable dependency into an in-memory backend.
package deployment

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

type Mode string

const (
	Development Mode = "development"
	SingleNode  Mode = "single-node"
	Standard    Mode = "standard"
	NetworkHA   Mode = "network-ha"
)

type Plan struct {
	Mode           Mode     `json:"mode"`
	Requested      string   `json:"requested"`
	Repository     string   `json:"repository"`
	Coordinator    string   `json:"coordinator"`
	Storage        string   `json:"storage"`
	SingleInstance bool     `json:"singleInstance"`
	LockPath       string   `json:"lockPath,omitempty"`
	Reasons        []string `json:"reasons"`
	Limitations    []string `json:"limitations,omitempty"`
	requireLocalFS bool
}

// Detect performs an offline, fail-closed topology selection. It must run before
// migrations or workers start. Run config.ValidateProduction separately for all
// security policy and signing-key checks. Availability is checked by the real
// connectors during bootstrap, not inferred from the presence of env variables.
func Detect(cfg config.Config) (Plan, error) {
	requested := strings.ToLower(strings.TrimSpace(cfg.DeploymentMode))
	if requested == "" {
		requested = "auto"
	}
	p := Plan{Requested: requested, Repository: strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver)), Storage: strings.ToLower(strings.TrimSpace(cfg.StorageDriver))}
	problems := []string{}
	switch requested {
	case "auto", string(SingleNode), string(Standard), string(NetworkHA):
	default:
		return p, fmt.Errorf("unsupported NEVERLAUNCHER_DEPLOYMENT_MODE=%q (auto|single-node|standard|network-ha)", requested)
	}
	if p.Storage == "" {
		p.Storage = "local"
	}
	if p.Repository == "" {
		p.Repository = "memory"
	}
	sqliteCoord := strings.TrimSpace(cfg.SQLiteCoordinatorPath) != ""
	if sqliteCoord {
		p.Coordinator = "sqlite"
	} else {
		p.Coordinator = "redis"
	}
	postgres := p.Repository == "postgres" || p.Repository == "postgresql" || p.Repository == "sql"
	sqliteRepo := p.Repository == "sqlite"
	memory := p.Repository == "memory" || p.Repository == "inmemory" || p.Repository == "in-memory"
	s3 := p.Storage == "s3" || p.Storage == "s3-compatible"

	switch {
	case requested != "auto":
		p.Mode = Mode(requested)
		p.Reasons = append(p.Reasons, "selected explicitly by NEVERLAUNCHER_DEPLOYMENT_MODE")
	case sqliteRepo:
		p.Mode = SingleNode
		p.Reasons = append(p.Reasons, "SQLite repository configured")
	case memory:
		p.Mode = Development
		p.Reasons = append(p.Reasons, "in-memory repository configured; development only")
	case postgres && sqliteCoord:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "PostgreSQL repository with local SQLite coordinator")
	case postgres && cfg.ServerBridgeHARequired && s3:
		p.Mode = NetworkHA
		p.Reasons = append(p.Reasons, "PostgreSQL, Redis HA policy and S3 storage are configured")
	case postgres:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "PostgreSQL repository; HA topology is incomplete or disabled")
	default:
		return p, fmt.Errorf("unsupported repository driver %q: no fallback to memory", p.Repository)
	}

	switch p.Mode {
	case Development:
		if config.IsProductionEnvironment(cfg.Environment) {
			problems = append(problems, "memory repository forbidden in production")
		}
		if requested != "auto" {
			problems = append(problems, "development is not a selectable production topology")
		}
	case SingleNode:
		// HTTP repository, auth/runtime stores and transactional stable admission
		// exist, but the installation wizard, recovery and bidirectional migration
		// remain unverified. Keep production minimal fail-closed until 0.37.5+ acceptance.
		if !sqliteRepo {
			problems = append(problems, "single-node requires a SQLite HTTP repository, not a PostgreSQL repository with SQLite coordinator")
		}
		problems = append(problems, "SQLite single-node production installation remains blocked pending installation, backup/restore and migration acceptance")
	case Standard, NetworkHA:
		if !postgres {
			problems = append(problems, "standard/network-ha require PostgreSQL HTTP repository")
		}
		if strings.ToLower(strings.TrimSpace(cfg.SQLDriver)) != "pgx" {
			problems = append(problems, "PostgreSQL requires pgx driver")
		}
		if strings.TrimSpace(cfg.DatabaseDSN) == "" {
			problems = append(problems, "PostgreSQL DSN is missing")
		}
		if sqliteCoord {
			if !filepath.IsAbs(cfg.SQLiteCoordinatorPath) {
				problems = append(problems, "SQLite coordinator path must be absolute")
			}
			if cfg.ServerBridgeHARequired {
				problems = append(problems, "SQLite coordinator cannot provide distributed HA")
			}
		}
		if config.IsProductionEnvironment(cfg.Environment) {
			if !cfg.RateLimitEnabled || !cfg.RateLimitFailClosed || cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
				problems = append(problems, "production requires enabled, fail-closed rate limiting with positive budgets")
			}
		}
		if p.Mode == NetworkHA {
			if sqliteCoord {
				problems = append(problems, "network-ha cannot use local SQLite coordinator")
			}
			if !cfg.ServerBridgeHARequired {
				problems = append(problems, "network-ha requires fenced ServerBridge HA")
			}
			if !s3 {
				problems = append(problems, "network-ha requires shared S3 storage; local files are not replicated")
			}
			if strings.TrimSpace(cfg.RedisURL) == "" {
				problems = append(problems, "network-ha requires Redis")
			}
			p.Reasons = append(p.Reasons, "multi-replica topology requires independently verified lease/fencing/failover")
		} else {
			p.SingleInstance = true
			p.requireLocalFS = config.IsProductionEnvironment(cfg.Environment)
			p.Limitations = append(p.Limitations, "one API process; not HA", "PostgreSQL remains required; SQLite coordinator does not replace the HTTP repository")
			lock := strings.TrimSpace(cfg.DeploymentLockPath)
			switch {
			case p.Storage == "local" && strings.TrimSpace(cfg.StorageLocalPath) != "":
				p.LockPath = filepath.Join(cfg.StorageLocalPath, ".neverlauncher-api.owner.lock")
				p.Reasons = append(p.Reasons, "instance lock anchored to shared local storage")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "local storage lock path cannot be overridden: all instances must lock the same storage root")
				}
			case sqliteCoord:
				p.LockPath = cfg.SQLiteCoordinatorPath + ".api.owner.lock"
				p.Reasons = append(p.Reasons, "instance lock anchored to SQLite coordinator volume")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "SQLite coordinator lock path cannot be overridden")
				}
			case lock != "":
				p.LockPath = lock
				p.Reasons = append(p.Reasons, "using explicit instance lock path")
			default:
				problems = append(problems, "standard with S3 requires NEVERLAUNCHER_DEPLOYMENT_LOCK_PATH on a shared, persistent local instance volume")
			}
			if p.LockPath != "" && !filepath.IsAbs(p.LockPath) {
				if config.IsProductionEnvironment(cfg.Environment) {
					problems = append(problems, "instance lock path must be absolute")
				} else {
					absolute, err := filepath.Abs(p.LockPath)
					if err != nil {
						problems = append(problems, "instance lock cannot resolve absolute path: "+err.Error())
					} else {
						p.LockPath = absolute
					}
				}
			}
		}
	}
	if len(problems) != 0 {
		return p, errors.New("deployment fail-closed: " + strings.Join(problems, "; "))
	}
	return p, nil
}
