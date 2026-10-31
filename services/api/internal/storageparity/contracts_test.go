package storageparity_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// This is a real-database, shared behavioral contract (not a mock repository).
// The currently different HTTP and SQLite Core APIs are adapted explicitly.
// Until DEP02 completes, this suite certifies ONLY the operations exercised here.
type storage interface {
	SaveProject(model.Project) (model.Project, error)
	GetProject(string) (model.Project, error)
	SaveProfile(model.Profile) (model.Profile, error)
	CurrentProfileSnapshot(string, string) (model.ProfileSnapshot, error)
	ListProfileRevisions(string, string) ([]model.ProfileSnapshot, error)
	SaveUser(model.User) (model.User, error)
	GetUserByEmail(string) (model.User, error)
	SetUserDisabled(string, bool) (model.User, error)
	IsConflict(error) bool
	Close() error
}

type sqliteAdapter struct{ repo *sqlitecore.Repository }

func (s *sqliteAdapter) SaveProject(p model.Project) (model.Project, error) {
	return s.repo.SaveProject(context.Background(), p, "parity-0371")
}
func (s *sqliteAdapter) GetProject(id string) (model.Project, error) {
	return s.repo.GetProject(context.Background(), id)
}
func (s *sqliteAdapter) SaveProfile(p model.Profile) (model.Profile, error) {
	return s.repo.SaveProfile(context.Background(), p, "parity-0371")
}
func (s *sqliteAdapter) CurrentProfileSnapshot(project, profile string) (model.ProfileSnapshot, error) {
	return s.repo.CurrentProfileSnapshot(context.Background(), project, profile)
}
func (s *sqliteAdapter) ListProfileRevisions(project, profile string) ([]model.ProfileSnapshot, error) {
	return s.repo.ListProfileRevisions(context.Background(), project, profile)
}
func (s *sqliteAdapter) SaveUser(u model.User) (model.User, error) {
	return s.repo.SaveUser(context.Background(), u, "parity-0371")
}
func (s *sqliteAdapter) GetUserByEmail(email string) (model.User, error) {
	return s.repo.GetUserByEmail(context.Background(), email)
}
func (s *sqliteAdapter) SetUserDisabled(id string, disabled bool) (model.User, error) {
	ctx := context.Background()
	if err := s.repo.SetUserDisabled(ctx, id, disabled, "parity-0371"); err != nil {
		return model.User{}, err
	}
	return s.repo.GetUser(ctx, id)
}
func (s *sqliteAdapter) IsConflict(err error) bool { return errors.Is(err, sqlitecore.ErrConflict) }
func (s *sqliteAdapter) Close() error              { return s.repo.Close() }

func sqliteFactory(t *testing.T) func() storage {
	t.Helper()
	base := os.Getenv("NEVERLAUNCHER_SQLITE_TEST_ROOT")
	if base == "" {
		base = t.TempDir()
	} else {
		base = filepath.Join(base, fmt.Sprintf("parity-%d", time.Now().UnixNano()))
		if err := os.Mkdir(base, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "parity.db")
	return func() storage {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r, err := sqlitecore.Open(ctx, sqlitedurable.Options{Path: path})
		if err != nil {
			t.Fatalf("real SQLite open (cannot substitute in-memory): %v", err)
		}
		return &sqliteAdapter{repo: r}
	}
}

// runCommon is used unchanged against both real database implementations.
// A restart is a fresh connection, never an in-memory snapshot replay.
func runCommon(t *testing.T, open func() storage, scope string) {
	t.Helper()
	s := open()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	id := "parity-0371-" + scope + "-" + suffix
	p, err := s.SaveProject(model.Project{ID: id, Name: "Parity project"})
	if err != nil {
		t.Fatalf("SaveProject: %v", err)
	}
	if p.ID != id || p.DefaultChannel != "stable" {
		t.Fatalf("project identity/default: %#v", p)
	}
	before := p.CreatedAt
	p.Name = "Parity renamed"
	p, err = s.SaveProject(p)
	if err != nil || p.CreatedAt.IsZero() || !p.CreatedAt.Equal(before) {
		t.Fatalf("upsert replaced createdAt: %#v %v", p, err)
	}

	// Real revision CAS and immutable revision-history guarantees.
	original, err := s.SaveProfile(model.Profile{ProjectID: id, ID: "client", Name: "Vanilla", Loader: "vanilla"})
	if err != nil || original.Revision != 1 {
		t.Fatalf("initial profile: %+v / %v", original, err)
	}
	initialSnapshot, err := s.CurrentProfileSnapshot(id, "client")
	if err != nil || initialSnapshot.Revision != 1 || initialSnapshot.Digest != original.Digest {
		t.Fatalf("initial snapshot: %+v / %v", initialSnapshot, err)
	}
	next := original
	next.Name = "Vanilla changed"
	updated, err := s.SaveProfile(next)
	if err != nil || updated.Revision != 2 || updated.Digest == original.Digest {
		t.Fatalf("CAS update: %+v / %v", updated, err)
	}
	stale := original
	stale.Name = "stale write"
	if _, err = s.SaveProfile(stale); !s.IsConflict(err) {
		t.Fatalf("stale revision not rejected: %v", err)
	}
	history, err := s.ListProfileRevisions(id, "client")
	if err != nil || len(history) != 2 || history[0].Revision != 1 || history[1].Revision != 2 {
		t.Fatalf("immutable history: %+v / %v", history, err)
	}
	if history[0].Spec.Name != "Vanilla" || history[1].Spec.Name != "Vanilla changed" {
		t.Fatalf("revision content modified: %+v", history)
	}

	// Cross-connection write race with the same revision: exactly one winner.
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := updated
			value.Name = fmt.Sprintf("winner-%d", i)
			_, err := s.SaveProfile(value)
			outcomes <- err
		}(i)
	}
	wg.Wait()
	close(outcomes)
	wins, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			wins++
		} else if s.IsConflict(err) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent write error: %v", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("CAS concurrency: winner=%d conflicts=%d", wins, conflicts)
	}

	// User identity and project roles survive a genuine backend reopen.
	u, err := s.SaveUser(model.User{ID: id + "-owner", Email: id + "@example.invalid", DisplayName: "Parity Owner", RoleID: "owner", Status: "active", ProjectRoles: map[string]string{id: "owner"}})
	if err != nil {
		t.Fatalf("SaveUser: %v", err)
	}
	if u.ProjectRoles[id] != "owner" {
		t.Fatalf("role binding missing: %+v", u.ProjectRoles)
	}
	// Account disable is security-critical: it must be durable and must not
	// erase project role bindings or accidentally re-enable on a stale read.
	disabled, err := s.SetUserDisabled(u.ID, true)
	if err != nil || disabled.Status != "disabled" || disabled.ProjectRoles[id] != "owner" {
		t.Fatalf("disable failed/roles lost: %+v / %v", disabled, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s = open()
	defer s.Close()
	restored, err := s.GetProject(id)
	if err != nil || restored.Name != "Parity renamed" || !restored.CreatedAt.Equal(before) {
		t.Fatalf("project lost after restart: %+v / %v", restored, err)
	}
	sn, err := s.CurrentProfileSnapshot(id, "client")
	if err != nil || sn.Revision != 3 {
		t.Fatalf("profile lost after restart: %+v / %v", sn, err)
	}
	h, err := s.ListProfileRevisions(id, "client")
	if err != nil || len(h) != 3 {
		t.Fatalf("revisions lost after restart: %d / %v", len(h), err)
	}
	user, err := s.GetUserByEmail(strings.ToUpper(u.Email))
	if err != nil || user.ID != u.ID || user.ProjectRoles[id] != "owner" || user.Status != "disabled" {
		t.Fatalf("user/status/roles lost after restart: %+v / %v", user, err)
	}
}

func TestSQLiteRealStorageParity0371(t *testing.T) {
	runCommon(t, sqliteFactory(t), "sqlite")
}
