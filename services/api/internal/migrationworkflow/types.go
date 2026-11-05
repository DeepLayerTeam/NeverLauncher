// Пакет migrationworkflow описывает сохраняемые состояния исполнения координатора
// миграций 0.33.1. Адаптеры источников, импорт и переключение не входят в 0.33.1.
package migrationworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("Не найдено: «migration run»")
	ErrBusy     = errors.New("migration run is leased, paused or not executable")
	ErrConflict = errors.New("migration run changed concurrently")
)

// Prepared означает сбор исходных сведений о целевом состоянии Never, а НЕ
// импорт, проверку или переключение проекта Gravit.
type Run struct {
	ID         string          `json:"id"`
	ProjectID  string          `json:"projectId"`
	SourceKind string          `json:"sourceKind"`
	Status     string          `json:"status"`
	Step       string          `json:"step"`
	Revision   int64           `json:"revision"`
	Fence      int64           `json:"fence"`
	Result     json.RawMessage `json:"result"`
	LastError  string          `json:"lastError,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
	UpdatedAt  time.Time       `json:"updatedAt"`
}

type Lease struct {
	Run   Run
	Owner string
	Fence int64
}

type Event struct {
	Sequence  int64           `json:"sequence"`
	Kind      string          `json:"kind"`
	Step      string          `json:"step"`
	Revision  int64           `json:"revision"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"createdAt"`
}

// Методы хранилища транзакционны и отклоняют операции с устаревшими токенами
// ограждения. Воркер с истёкшей арендой не может записать контрольную точку после
// передачи работы новому воркеру.
type Store interface {
	CreateMigration0331(context.Context, string, string, string) (Run, error)
	GetMigration0331(context.Context, string) (Run, error)
	ListMigrations0331(context.Context, string) ([]Run, error)
	ClaimMigration0331(context.Context, string, string, time.Duration) (Lease, error)
	CheckpointMigration0331(context.Context, Lease, string, json.RawMessage) (Run, error)
	FailMigration0331(context.Context, Lease, string) (Run, error)
	PauseMigration0331(context.Context, string) (Run, error)
	ResumeMigration0331(context.Context, string) (Run, error)
	MigrationEvents0331(context.Context, string, int64, int) ([]Event, error)
}
