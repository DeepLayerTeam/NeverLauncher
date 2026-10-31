//go:build !launcher_nopgx

package storageparity_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type postgresAdapter struct{ repo *repository.SQLRepository }

func (p *postgresAdapter) SaveProject(v model.Project) (model.Project, error) {
	return p.repo.SaveProject(v)
}
func (p *postgresAdapter) GetProject(id string) (model.Project, error) { return p.repo.GetProject(id) }
func (p *postgresAdapter) SaveProfile(v model.Profile) (model.Profile, error) {
	return p.repo.SaveProfile(v)
}
func (p *postgresAdapter) CurrentProfileSnapshot(project, profile string) (model.ProfileSnapshot, error) {
	return p.repo.CurrentProfileSnapshot(project, profile)
}
func (p *postgresAdapter) ListProfileRevisions(project, profile string) ([]model.ProfileSnapshot, error) {
	return p.repo.ListProfileRevisions(project, profile)
}
func (p *postgresAdapter) SaveUser(u model.User) (model.User, error) { return p.repo.SaveUser(u) }
func (p *postgresAdapter) GetUserByEmail(email string) (model.User, error) {
	return p.repo.GetUserByEmail(email)
}
func (p *postgresAdapter) SetUserDisabled(id string, disabled bool) (model.User, error) {
	return p.repo.SetUserDisabled(id, disabled)
}
func (p *postgresAdapter) IsConflict(err error) bool { return errors.Is(err, repository.ErrConflict) }
func (p *postgresAdapter) Close() error              { return p.repo.Close() }

// A disposable PostgreSQL DSN is mandatory for the dedicated CI job. Neither
// SQLite nor an in-memory fallback can satisfy this test.
func TestPostgresRealStorageParity0371(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_PARITY_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("LAUNCHER_STORAGE_PARITY_REQUIRED") == "1" {
			t.Fatal("LAUNCHER_PARITY_POSTGRES_DSN required for production parity gate")
		}
		t.Skip("requires disposable LAUNCHER_PARITY_POSTGRES_DSN")
	}
	makeRepo := func() *repository.SQLRepository {
		r, ok := repository.NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*repository.SQLRepository)
		if !ok {
			t.Fatal("Postgres factory returned wrong type")
		}
		return r
	}
	migrate := makeRepo()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := migrate.ApplyMigrations(ctx); err != nil {
		t.Fatalf("Postgres migration: %v", err)
	}
	if err := migrate.Close(); err != nil {
		t.Fatal(err)
	}
	runCommon(t, func() storage { return &postgresAdapter{repo: makeRepo()} }, "postgres")
}
