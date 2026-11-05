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
		p.Reasons = append(p.Reasons, "Режим явно выбран через LAUNCHER_DEPLOYMENT_MODE")
	case sqliteRepo:
		p.Mode = SingleNode
		p.Reasons = append(p.Reasons, "Настроен репозиторий SQLite")
	case memory:
		p.Mode = Development
		p.Reasons = append(p.Reasons, "Настроен репозиторий в памяти; только для разработки")
	case postgres && sqliteCoord:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "Репозиторий PostgreSQL с локальным координатором SQLite")
	case postgres && cfg.ServerBridgeHARequired && s3:
		p.Mode = NetworkHA
		p.Reasons = append(p.Reasons, "Настроены PostgreSQL, политика высокой доступности Redis и хранилище S3")
	case postgres:
		p.Mode = Standard
		p.Reasons = append(p.Reasons, "Репозиторий PostgreSQL; конфигурация высокой доступности неполна или отключена")
	default:
		return p, fmt.Errorf("Неподдерживаемый драйвер репозитория %q: переход на репозиторий в памяти запрещён", p.Repository)
	}

	switch p.Mode {
	case Development:
		if config.IsProductionEnvironment(cfg.Environment) {
			problems = append(problems, "В рабочем окружении запрещён репозиторий в памяти")
		}
		if requested != "auto" {
			problems = append(problems, "Режим разработки нельзя выбирать для рабочего развёртывания")
		}
	case SingleNode:
		if !sqliteRepo {
			problems = append(problems, "Для одноузлового режима требуется HTTP-репозиторий SQLite")
		}
		if p.Storage != "local" {
			problems = append(problems, "Для одноузлового режима требуется локальное объектное хранилище")
		}
		if cfg.ServerBridgeHARequired {
			problems = append(problems, "Одноузловой режим не поддерживает распределённую высокую доступность ServerBridge")
		}
		if strings.TrimSpace(cfg.RedisURL) != "" {
			problems = append(problems, "В одноузловом режиме нельзя настраивать Redis; используется только локальная координация SQLite")
		}
		for label, path := range map[string]string{"repository": cfg.DatabaseDSN, "coordinator": cfg.SQLiteCoordinatorPath, "storage": cfg.StorageLocalPath} {
			if strings.TrimSpace(path) == "" || (config.IsProductionEnvironment(cfg.Environment) && (!filepath.IsAbs(path) || filepath.Clean(path) != path)) {
				problems = append(problems, "Одноузловой режим: "+label+" — требуется абсолютный нормализованный путь к постоянному хранилищу")
			}
		}
		if filepath.Clean(cfg.DatabaseDSN) == filepath.Clean(cfg.SQLiteCoordinatorPath) {
			problems = append(problems, "Репозиторий и координатор должны использовать разные файлы SQLite")
		}
		if cfg.RateLimitEnabled == false || !cfg.RateLimitFailClosed || cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
			problems = append(problems, "Одноузловой режим требует включённого ограничения частоты запросов с блокировкой при сбое и положительными лимитами")
		}
		p.Coordinator = "sqlite"
		p.SingleInstance = true
		p.requireLocalFS = true
		p.Limitations = append(p.Limitations, "Только один процесс API в Linux; распределённая высокая доступность отсутствует", "Для миграции SQLite в PostgreSQL требуется отдельная проверенная процедура")
		// Корневой каталог хранилища — каноническая точка привязки владения между
		// развёртываниями.
		p.LockPath = filepath.Join(cfg.StorageLocalPath, ".launcher-api.owner.lock")
		if lock := strings.TrimSpace(cfg.DeploymentLockPath); lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
			problems = append(problems, "Блокировку владельца одноузлового режима нельзя переопределить")
		}
		p.Reasons = append(p.Reasons, "Исключительное владение локальным процессом; отказоустойчивые HTTP-репозиторий и координатор SQLite")
	case Standard, NetworkHA:
		if !postgres {
			problems = append(problems, "Стандартному режиму и режиму Network HA требуется HTTP-репозиторий PostgreSQL")
		}
		if strings.ToLower(strings.TrimSpace(cfg.SQLDriver)) != "pgx" {
			problems = append(problems, "Для PostgreSQL требуется драйвер pgx")
		}
		if strings.TrimSpace(cfg.DatabaseDSN) == "" {
			problems = append(problems, "DSN PostgreSQL не задан")
		}
		if sqliteCoord {
			if !filepath.IsAbs(cfg.SQLiteCoordinatorPath) {
				problems = append(problems, "Путь координатора SQLite должен быть абсолютным")
			}
			if cfg.ServerBridgeHARequired {
				problems = append(problems, "Координатор SQLite не поддерживает распределённую высокую доступность")
			}
		}
		if config.IsProductionEnvironment(cfg.Environment) {
			if !cfg.RateLimitEnabled || !cfg.RateLimitFailClosed || cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
				problems = append(problems, "В рабочем окружении требуется включённое ограничение частоты запросов с блокировкой при сбое и положительными лимитами")
			}
		}
		if p.Mode == NetworkHA {
			// Маршрутизация и владение арендой привязаны к этой идентичности для API и
			// workers. Запасной ID из PID/hostname меняется при перезапуске и может
			// конфликтовать в клонированных контейнерах; отклоняйте его для Network-HA.
			id := strings.TrimSpace(cfg.ServerBridgeReplicaID)
			if id == "" {
				problems = append(problems, "Network HA требует явно заданный постоянный LAUNCHER_REPLICA_ID для каждого API и рабочего процесса")
			} else if len(id) > 128 || strings.ContainsAny(id, " \t\r\n/\\") {
				problems = append(problems, "LAUNCHER_REPLICA_ID для Network HA должен быть постоянным идентификатором длиной не более 128 байт без пробельных символов")
			}
			if sqliteCoord {
				problems = append(problems, "Network HA не может использовать локальный координатор SQLite")
			}
			if !cfg.ServerBridgeHARequired {
				problems = append(problems, "Для Network HA требуется ServerBridge HA с защитой от параллельного владения")
			}
			if !s3 {
				problems = append(problems, "Для Network HA требуется общее хранилище S3; локальные файлы не реплицируются")
			}
			if strings.TrimSpace(cfg.RedisURL) == "" {
				problems = append(problems, "Для Network HA требуется Redis")
			}
			p.Reasons = append(p.Reasons, "Конфигурация с несколькими репликами требует независимой проверки аренды, защиты от параллельного владения и переключения при отказе")
		} else {
			p.SingleInstance = true
			p.requireLocalFS = config.IsProductionEnvironment(cfg.Environment)
			p.Limitations = append(p.Limitations, "Один процесс API; высокой доступности нет", "PostgreSQL по-прежнему необходим; координатор SQLite не заменяет HTTP-репозиторий")
			lock := strings.TrimSpace(cfg.DeploymentLockPath)
			switch {
			case p.Storage == "local" && strings.TrimSpace(cfg.StorageLocalPath) != "":
				p.LockPath = filepath.Join(cfg.StorageLocalPath, ".launcher-api.owner.lock")
				p.Reasons = append(p.Reasons, "Блокировка экземпляра привязана к общему локальному хранилищу")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "Путь блокировки локального хранилища нельзя переопределять: все экземпляры должны блокировать один корень хранилища")
				}
			case sqliteCoord:
				p.LockPath = cfg.SQLiteCoordinatorPath + ".api.owner.lock"
				p.Reasons = append(p.Reasons, "Блокировка экземпляра привязана к тому координатора SQLite")
				if lock != "" && filepath.Clean(lock) != filepath.Clean(p.LockPath) {
					problems = append(problems, "Путь блокировки координатора SQLite нельзя переопределить")
				}
			case lock != "":
				p.LockPath = lock
				p.Reasons = append(p.Reasons, "Используется явно заданный путь блокировки экземпляра")
			default:
				problems = append(problems, "Стандартный режим с S3 требует LAUNCHER_DEPLOYMENT_LOCK_PATH на общем постоянном локальном томе экземпляра")
			}
			if p.LockPath != "" && !filepath.IsAbs(p.LockPath) {
				if config.IsProductionEnvironment(cfg.Environment) {
					problems = append(problems, "Путь блокировки экземпляра должен быть абсолютным")
				} else {
					absolute, err := filepath.Abs(p.LockPath)
					if err != nil {
						problems = append(problems, "Не удалось получить абсолютный путь блокировки экземпляра: "+err.Error())
					} else {
						p.LockPath = absolute
					}
				}
			}
		}
	}
	if len(problems) != 0 {
		return p, errors.New("Развёртывание остановлено из-за ошибки проверки: " + strings.Join(problems, "; "))
	}
	return p, nil
}
