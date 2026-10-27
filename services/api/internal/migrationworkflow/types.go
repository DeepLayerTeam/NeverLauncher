// Package migrationworkflow defines persisted execution states for the 0.33.1
// migration coordinator. Source adapters, importing and cutover are not in 0.33.1.
package migrationworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("migration run not found")
	ErrBusy     = errors.New("migration run is leased, paused or not executable")
	ErrConflict = errors.New("migration run changed concurrently")
)

// Prepared means the Never target baseline was collected, NOT that a Gravit
// project was imported, verified, or cut over.
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

// Store methods are transactional and reject operations with stale fencing
// tokens. An expired worker can never checkpoint after a new worker takes over.
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
