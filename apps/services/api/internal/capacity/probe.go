package capacity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Пороги — консервативные ЭКСПЛУАТАЦИОННЫЕ сигналы, а не сертифицированные
// максимумы пропускной способности. Реальный подбор ресурсов требует тестов на
// целевом оборудовании.
const (
	MinDiskFreeBytes           uint64 = 2 << 30
	MinDiskFreeFraction               = 0.10
	ConnectionsWarningFraction        = 0.80
	QueueWarningSize           int64  = 500
	OldestJobWarning                  = 60 * time.Second
	HTTPP95Warning                    = time.Second
)

type Options struct {
	Mode            string
	DatabaseDSN     string
	CoordinatorPath string
	StoragePath     string
	BackupPath      string
	Driver          string
	Traffic         *HTTPMetrics
}
type Disk struct {
	Name              string  `json:"name"`
	CapacityBytes     uint64  `json:"capacityBytes"`
	AvailableBytes    uint64  `json:"availableBytes"`
	AvailableFraction float64 `json:"availableFraction"`
	DataBytes         int64   `json:"dataBytes,omitempty"`
}
type PostgreSQL struct {
	DatabaseBytes           int64   `json:"databaseBytes"`
	Projects                int64   `json:"projects"`
	Users                   int64   `json:"users"`
	Roles                   int64   `json:"roles"`
	AuditEvents             int64   `json:"auditEvents"`
	TelemetryEvents         int64   `json:"telemetryEvents"`
	CrashReports            int64   `json:"crashReports"`
	ActiveConnections       int64   `json:"activeConnections"`
	MaxConnections          int64   `json:"maxConnections"`
	PendingJobs             int64   `json:"pendingJobs"`
	ExpiredJobLeases        int64   `json:"expiredJobLeases"`
	PendingOutbox           int64   `json:"pendingOutbox"`
	OldestPendingJobSeconds float64 `json:"oldestPendingJobSeconds"`
}
type Issue struct {
	Severity       string `json:"severity"`
	Metric         string `json:"metric"`
	Observed       string `json:"observed"`
	Condition      string `json:"condition"`
	Recommendation string `json:"recommendation"`
}
type Report struct {
	Mode        string      `json:"mode"`
	At          time.Time   `json:"at"`
	Source      string      `json:"source"`
	GoHeapBytes uint64      `json:"goHeapBytes"`
	Goroutines  int         `json:"goroutines"`
	Traffic     Traffic     `json:"traffic"`
	Disks       []Disk      `json:"disks,omitempty"`
	PostgreSQL  *PostgreSQL `json:"postgresql,omitempty"`
	Issues      []Issue     `json:"issues"`
	Errors      []string    `json:"errors,omitempty"`
	Limitations []string    `json:"limitations"`
	Verified    bool        `json:"verified"`
}

func (r *Report) issue(level, metric, observed, condition, advice string) {
	r.Issues = append(r.Issues, Issue{level, metric, observed, condition, advice})
}

// Probe собирает фактические показатели ОС и БД. Каждая неудачная обязательная
// проверка видна и помечает отчёт как непроверенный; ноль никогда не подставляется
// как выдуманный успешный результат.
func Probe(ctx context.Context, opt Options) Report {
	r := Report{Mode: opt.Mode, At: time.Now().UTC(), Source: "Текущие показания; пороги используются для эксплуатационного контроля, а не для измерения производительности", Issues: []Issue{}, Verified: true, Limitations: []string{"Ёмкость и квоту S3 нельзя определить через переносимый API S3", "Распределённое переключение при отказе и ограждение требуют отдельной диагностики роста нагрузки и проверки на нескольких узлах"}}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.GoHeapBytes = ms.HeapAlloc
	r.Goroutines = runtime.NumGoroutine()
	if opt.Traffic != nil {
		r.Traffic = opt.Traffic.Snapshot(time.Now())
	}
	for _, p := range []struct{ name, path string }{{"storage", opt.StoragePath}, {"sqlite-coordinator", opt.CoordinatorPath}, {"backup", opt.BackupPath}} {
		if p.path == "" {
			continue
		}
		d, err := measureDisk(p.name, p.path)
		if err != nil {
			r.Errors = append(r.Errors, p.name+": "+err.Error())
			r.Verified = false
			continue
		}
		r.Disks = append(r.Disks, d)
		if d.AvailableBytes < MinDiskFreeBytes || d.AvailableFraction < MinDiskFreeFraction {
			r.issue("critical", p.name+".free", fmt.Sprintf("%d bytes / %.1f%%", d.AvailableBytes, d.AvailableFraction*100), "Доступно менее 2 ГиБ или 10 % объёма", "Освободите место или перенесите данные и резервные копии на другой том; перед расширением проверьте восстановление")
		}
	}
	if strings.EqualFold(opt.Driver, "postgres") || strings.EqualFold(opt.Driver, "postgresql") || strings.EqualFold(opt.Driver, "sql") {
		if opt.DatabaseDSN == "" {
			r.Errors = append(r.Errors, "DSN PostgreSQL не задан")
			r.Verified = false
		} else {
			db, err := sql.Open("pgx", opt.DatabaseDSN)
			if err != nil {
				r.Errors = append(r.Errors, "PostgreSQL open: "+err.Error())
				r.Verified = false
			} else {
				// Ограниченная по времени проба не должна истощать обычный пул соединений
				// приложения.
				db.SetMaxOpenConns(2)
				db.SetMaxIdleConns(0)
				pg, probeErr := probePostgres(ctx, db)
				_ = db.Close()
				if probeErr != nil {
					r.Errors = append(r.Errors, "PostgreSQL probe: "+probeErr.Error())
					r.Verified = false
				} else {
					r.PostgreSQL = &pg
					r.evaluatePostgres(pg)
				}
			}
		}
	}
	if r.Traffic.Requests >= 20 {
		if r.Traffic.P95Seconds > HTTPP95Warning.Seconds() {
			r.issue("warning", "http.p95", fmt.Sprintf("%.3fs", r.Traffic.P95Seconds), "p95 превышает 1 с за последние 60 секунд", "Profile hot handlers and DB queries; scale Backend only after checking shared dependencies")
		}
		if r.Traffic.ErrorRatio >= .05 {
			r.issue("critical", "http.5xx", fmt.Sprintf("%.1f%%", 100*r.Traffic.ErrorRatio), "Доля ответов 5xx за последние 60 секунд достигла 5 %", "Проверьте журналы и готовность системы перед добавлением реплик")
		}
		if r.Traffic.ThrottleRatio >= .10 {
			r.issue("warning", "http.429", fmt.Sprintf("%.1f%%", 100*r.Traffic.ThrottleRatio), "429 >= 10% in last 60s", "Проанализируйте подозрительный трафик и повторные запросы клиентов; увеличивайте лимиты только на основе проверенных данных")
		}
	}
	return r
}
func (r *Report) evaluatePostgres(p PostgreSQL) {
	if p.MaxConnections > 0 && float64(p.ActiveConnections)/float64(p.MaxConnections) >= ConnectionsWarningFraction {
		r.issue("warning", "postgres.connections", fmt.Sprintf("%d/%d", p.ActiveConnections, p.MaxConnections), ">= 80% max_connections", "Устраните утечки и простаивающие соединения, настройте ограниченные пулы; рассмотрите PgBouncer перед увеличением числа реплик API")
	}
	if p.PendingJobs >= QueueWarningSize {
		r.issue("warning", "jobs.pending", fmt.Sprint(p.PendingJobs), ">= 500 pending jobs", "Проверьте сбойные обработчики и частоту повторов; увеличивайте параллелизм только после проверки аренды и механизма fencing")
	}
	if p.OldestPendingJobSeconds > OldestJobWarning.Seconds() && p.PendingJobs > 0 {
		r.issue("warning", "jobs.oldest_pending", fmt.Sprintf("%.0fs", p.OldestPendingJobSeconds), "> 60s oldest pending job", "Проверьте состояние обработчиков, производительность БД и политику повторного запуска заданий")
	}
	if p.ExpiredJobLeases > 0 {
		r.issue("warning", "jobs.expired_leases", fmt.Sprint(p.ExpiredJobLeases), "> 0 просроченных аренд выполняющихся заданий", "Проверьте сбои обработчиков и ограждение; не повторяйте вслепую операции без идемпотентности")
	}
	if p.PendingOutbox >= QueueWarningSize {
		r.issue("warning", "outbox.pending", fmt.Sprint(p.PendingOutbox), ">= 500 pending events", "Проверьте обработчик исходящих событий и подтверждения получателей; сохраните идемпотентность при доставке не реже одного раза")
	}
}
func probePostgres(ctx context.Context, db *sql.DB) (PostgreSQL, error) {
	var p PostgreSQL
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var maxText string
	// MAX connections относится ко всему серверу, активные соединения — тоже.
	if err := db.QueryRowContext(ctx, "SHOW max_connections").Scan(&maxText); err != nil {
		return p, err
	}
	if _, err := fmt.Sscan(maxText, &p.MaxConnections); err != nil {
		return p, fmt.Errorf("Некорректное значение: max_connections: %w", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'").Scan(&p.ActiveConnections); err != nil {
		return p, err
	}
	if err := db.QueryRowContext(ctx, "SELECT pg_database_size(current_database())").Scan(&p.DatabaseBytes); err != nil {
		return p, err
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status='pending'), count(*) FILTER (WHERE status='running' AND lease_expires_at<now()), COALESCE(EXTRACT(EPOCH FROM (now()-MIN(created_at) FILTER (WHERE status='pending'))),0) FROM durable_jobs`).Scan(&p.PendingJobs, &p.ExpiredJobLeases, &p.OldestPendingJobSeconds); err != nil {
		return p, err
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM event_outbox WHERE status='pending'").Scan(&p.PendingOutbox); err != nil {
		return p, err
	}
	// Сохраняйте существующие агрегированные счётчики Prometheus, не загружая при
	// каждом HTTP-опросе полные списки объектов в память.
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM projects),
 (SELECT count(*) FROM users), (SELECT count(*) FROM roles),
 (SELECT count(*) FROM audit_events), (SELECT count(*) FROM telemetry_events),
 (SELECT count(*) FROM crash_reports)`).Scan(&p.Projects, &p.Users, &p.Roles, &p.AuditEvents, &p.TelemetryEvents, &p.CrashReports); err != nil {
		return p, err
	}
	return p, nil
}

// measureDisk реализуется отдельными платформенными функциями.
func canonicalExistingDir(path string) (string, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if st, e := os.Stat(p); e == nil && !st.IsDir() {
		p = filepath.Dir(p)
	} else if e != nil && errors.Is(e, os.ErrNotExist) {
		p = filepath.Dir(p)
	}
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}
