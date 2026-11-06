// Package deployment выбирает и обеспечивает фактическую поддерживаемую топологию
// API. Он никогда не подменяет недоступную устойчивую зависимость внутренним
// хранилищем в памяти.
package deployment

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
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

// Detect выбирает топологию автономно с отказом при ошибке. Запускайте его до
// миграций и рабочих процессов. Отдельно выполняйте config.ValidateProduction для
// всех политик безопасности и ключей подписи. Доступность проверяют реальные
// коннекторы при начальной загрузке.
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
		return p, fmt.Errorf("Не поддерживается: «LAUNCHER_DEPLOYMENT_MODE=%q (auto|single-node|standard|network-ha)»", requested)
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
		p.Reasons = append(p.Reasons, "Выбрано явно через LAUNCHER_DEPLOYMENT_MODE")
	case sqliteRepo:
		p.Mode = SingleNode
		p.Reasons = append(p.Reasons, "Настроен репозиторий SQLite")
	case memory:
		p.Mode = Development
		p.Reasons = append(p.Reasons, "Настроено хранилище в памяти; только для разработки")
	case postgres && sqliteCoord:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "Репозиторий PostgreSQL с локальным координатором SQLite")
	case postgres && cfg.ServerBridgeHARequired && s3:
		p.Mode = NetworkHA
		p.Reasons = append(p.Reasons, "Настроены PostgreSQL, политика высокой доступности Redis и хранилище S3")
	case postgres:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "Репозиторий PostgreSQL; конфигурация высокой доступности не завершена или отключена")
	default:
		return p, fmt.Errorf("Не поддерживается: «repository driver %q: no fallback to memory»", p.Repository)
	}

	switch p.Mode {
	case Development:
		if config.IsProductionEnvironment(cfg.Environment) {
			problems = append(problems, "Хранилище в памяти запрещено в рабочем окружении")
		}
		if requested != "auto" {
			problems = append(problems, "Топологию development нельзя выбрать для рабочего окружения")
		}
	case SingleNode:
		if !sqliteRepo {
			problems = append(problems, "Для одноузлового режима требуется HTTP-хранилище SQLite")
		}
		if p.Storage != "local" {
			problems = append(problems, "Для одноузлового режима необходимо локальное объектное хранилище")
		}
		if cfg.ServerBridgeHARequired {
			problems = append(problems, "Одиночный узел не может обеспечить распределённую отказоустойчивость ServerBridge")
		}
		if strings.TrimSpace(cfg.RedisURL) != "" {
			problems = append(problems, "На одиночном узле нельзя настраивать Redis; допускается только локальная координация SQLite")
		}
		for label, path := range map[string]string{"repository": cfg.DatabaseDSN, "coordinator": cfg.SQLiteCoordinatorPath, "storage": cfg.StorageLocalPath} {
			if strings.TrimSpace(path) == "" || (config.IsProductionEnvironment(cfg.Environment) && (!filepath.IsAbs(path) || filepath.Clean(path) != path)) {
				problems = append(problems, "single-node "+label+" требуется абсолютный путь к чистому каталогу постоянного хранения")
			}
		}
		if filepath.Clean(cfg.DatabaseDSN) == filepath.Clean(cfg.SQLiteCoordinatorPath) {
			problems = append(problems, "Хранилище и координатор должны использовать разные файлы SQLite")
		}
		if cfg.RateLimitEnabled == false || !cfg.RateLimitFailClosed || cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
			problems = append(problems, "Для одноузлового режима необходимо включить ограничения частоты запросов с отказом при сбое и положительными лимитами")
		}
		p.Coordinator = "sqlite"
		p.SingleInstance = true
		p.requireLocalFS = true
		p.Limitations = append(p.Limitations, "Допускается только один процесс Linux API; распределённая отказоустойчивость недоступна", "Перенос с SQLite на PostgreSQL требует отдельной проверенной процедуры")
		// Корневой каталог хранилища — каноническая точка привязки владения между
		// развёртываниями.
		p.LockPath = filepath.Join(cfg.StorageLocalPath, ".launcher-api.owner.lock")
		if lock := strings.TrimSpace(cfg.DeploymentLockPath); lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
			problems = append(problems, "Нельзя переопределить блокировку владельца одиночного узла")
		}
		p.Reasons = append(p.Reasons, "Единственный локальный процесс-владелец; сохраняемый HTTP-репозиторий SQLite и координатор")
	case Standard, NetworkHA:
		if !postgres {
			problems = append(problems, "Для standard/network-ha требуется HTTP-хранилище PostgreSQL")
		}
		if strings.ToLower(strings.TrimSpace(cfg.SQLDriver)) != "pgx" {
			problems = append(problems, "Для PostgreSQL требуется драйвер pgx")
		}
		if strings.TrimSpace(cfg.DatabaseDSN) == "" {
			problems = append(problems, "Отсутствует строка подключения PostgreSQL (DSN)")
		}
		if sqliteCoord {
			if !filepath.IsAbs(cfg.SQLiteCoordinatorPath) {
				problems = append(problems, "Путь координатора SQLite должен быть абсолютным")
			}
			if cfg.ServerBridgeHARequired {
				problems = append(problems, "Координатор SQLite не может обеспечить распределённую отказоустойчивость")
			}
		}
		if config.IsProductionEnvironment(cfg.Environment) {
			if !cfg.RateLimitEnabled || !cfg.RateLimitFailClosed || cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
				problems = append(problems, "Для рабочей среды необходимы включённые ограничения частоты запросов с отказом при сбое и положительными лимитами")
			}
		}
		if p.Mode == NetworkHA {
			// Маршрутизация и владение арендой привязаны к этой идентичности для API и
			// workers. Запасной ID из PID/hostname меняется при перезапуске и может
			// конфликтовать в клонированных контейнерах; отклоняйте его для Network-HA.
			id := strings.TrimSpace(cfg.ServerBridgeReplicaID)
			if id == "" {
				problems = append(problems, "Для network-ha нужен явно настроенный постоянный LAUNCHER_REPLICA_ID каждого экземпляра API и обработчика")
			} else if len(id) > 128 || strings.ContainsAny(id, " \t\r\n/\\") {
				problems = append(problems, "Для network-ha LAUNCHER_REPLICA_ID должен быть устойчивым непустым идентификатором без пробелов длиной не более 128 байт")
			}
			if sqliteCoord {
				problems = append(problems, "Режим network-ha не может использовать локальный координатор SQLite")
			}
			if !cfg.ServerBridgeHARequired {
				problems = append(problems, "Для network-ha необходим ServerBridge HA с механизмом ограждения")
			}
			if !s3 {
				problems = append(problems, "Для network-ha необходимо общее S3-хранилище; локальные файлы не реплицируются")
			}
			if strings.TrimSpace(cfg.RedisURL) == "" {
				problems = append(problems, "Для режима network-ha требуется Redis")
			}
			p.Reasons = append(p.Reasons, "Для многорепликовой конфигурации необходима независимая проверка аренды, изоляции и переключения при сбое")
		} else {
			p.SingleInstance = true
			p.requireLocalFS = config.IsProductionEnvironment(cfg.Environment)
			p.Limitations = append(p.Limitations, "Один процесс API; без высокой доступности", "PostgreSQL остаётся обязательным; координатор SQLite не заменяет HTTP-хранилище")
			lock := strings.TrimSpace(cfg.DeploymentLockPath)
			switch {
			case p.Storage == "local" && strings.TrimSpace(cfg.StorageLocalPath) != "":
				p.LockPath = filepath.Join(cfg.StorageLocalPath, ".launcher-api.owner.lock")
				p.Reasons = append(p.Reasons, "Блокировка экземпляра привязана к общему локальному хранилищу")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "Нельзя переопределять путь блокировки локального хранилища: все экземпляры должны блокировать один корневой каталог")
				}
			case sqliteCoord:
				p.LockPath = cfg.SQLiteCoordinatorPath + ".api.owner.lock"
				p.Reasons = append(p.Reasons, "Блокировка экземпляра привязана к тому координатора SQLite")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "Нельзя переопределить путь блокировки координатора SQLite")
				}
			case lock != "":
				p.LockPath = lock
				p.Reasons = append(p.Reasons, "Используется явно заданный путь блокировки экземпляра")
			default:
				problems = append(problems, "standard with S3 requires LAUNCHER_DEPLOYMENT_LOCK_PATH on a shared, persistent local instance volume")
			}
			if p.LockPath != "" && !filepath.IsAbs(p.LockPath) {
				if config.IsProductionEnvironment(cfg.Environment) {
					problems = append(problems, "Путь блокировки экземпляра должен быть абсолютным")
				} else {
					absolute, err := filepath.Abs(p.LockPath)
					if err != nil {
						problems = append(problems, "Не удалось определить абсолютный путь блокировки экземпляра: "+err.Error())
					} else {
						p.LockPath = absolute
					}
				}
			}
		}
	}
	if len(problems) != 0 {
		return p, errors.New("Развёртывание остановлено по принципу безопасного отказа: " + strings.Join(problems, "; "))
	}
	return p, nil
}
