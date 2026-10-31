package repository

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// A field added to the domain model must not silently be dropped during
// persistence. This test is intentionally in the repository package.
func TestSQLiteHTTPStateCoverage0372(t *testing.T) {
	source := reflect.TypeOf(MemoryRepository{})
	persisted := reflect.TypeOf(sqliteHTTPState0372{})
	got := map[string]reflect.Type{}
	for i := 0; i < persisted.NumField(); i++ {
		f := persisted.Field(i)
		got[strings.ToLower(f.Name[:1])+f.Name[1:]] = f.Type
	}
	for i := 0; i < source.NumField(); i++ {
		f := source.Field(i)
		if f.Type == reflect.TypeOf(sync.Mutex{}) || f.Type == reflect.TypeOf(sync.RWMutex{}) || f.Type.Kind() == reflect.Func {
			continue
		}
		if v, ok := got[f.Name]; !ok || v != f.Type {
			t.Errorf("HTTP state field %s (%s) is not persisted with matching type", f.Name, f.Type)
		}
	}
}

func TestSQLiteHTTPPersistenceAndCAS0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "http-repository.db")
	open := func() *SQLiteHTTPRepository0372 {
		r, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://example")
		if err != nil {
			t.Fatalf("open real SQLite WAL repository: %v", err)
		}
		return r
	}
	r := open()
	if len(r.ListProjects()) != 0 || len(r.ListUsers()) != 0 {
		t.Fatal("a new SQLite installation must not inherit development projects or admin credentials")
	}
	if err := r.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SaveUser(model.User{ID: "unapproved", Email: "viewer@example.test", RoleID: "viewer"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("first account must be active owner: %v", err)
	}
	project, err := r.SaveProject(model.Project{ID: "real-project", Name: "Real project"})
	if err != nil || project.ID != "real-project" {
		t.Fatalf("save project: %+v / %v", project, err)
	}
	p, err := r.SaveProfile(model.Profile{ProjectID: project.ID, ID: "client", Name: "Vanilla", Loader: "vanilla"})
	if err != nil || p.Revision != 1 {
		t.Fatalf("save profile: %+v / %v", p, err)
	}
	current := p
	current.Name = "Updated"
	updated, err := r.SaveProfile(current)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("CAS revision: %+v / %v", updated, err)
	}
	current.Name = "Stale edit"
	if _, err := r.SaveProfile(current); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale CAS conflict, got %v", err)
	}
	if _, err := r.SaveUser(model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner", Status: "active"}); err != nil {
		t.Fatalf("owner: %v", err)
	}
	if _, err := r.SetUserDisabled("owner", true); !errors.Is(err, ErrConflict) {
		t.Fatalf("last owner was disabled: %v", err)
	}
	if _, err := OpenSQLiteHTTPRepository0372(ctx, path, ""); err == nil {
		t.Fatal("second writer acquired the same SQLite file")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = open()
	defer r.Close()
	if err := r.Health(ctx); err != nil {
		t.Fatalf("reopen readiness: %v", err)
	}
	if got, err := r.GetProject(project.ID); err != nil || got.Name != project.Name {
		t.Fatalf("project lost on restart: %+v / %v", got, err)
	}
	profiles, err := r.ListProfiles(project.ID)
	if err != nil || len(profiles) != 1 || profiles[0].Revision != 2 || profiles[0].Name != "Updated" {
		t.Fatalf("profile revision lost on restart: %+v / %v", profiles, err)
	}
	history, err := r.ListProfileRevisions(project.ID, "client")
	if err != nil || len(history) != 2 {
		t.Fatalf("history lost on restart: %+v / %v", history, err)
	}
	if _, err := r.GetUserByEmail("owner@example.test"); err != nil {
		t.Fatalf("owner lost on restart: %v", err)
	}
	if len(r.ListUsers()) != 1 {
		t.Fatal("unexpected development user after reopen")
	}
}

func TestSQLiteHTTPConcurrentWritesAndSafeFailure0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "concurrency.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	const n = 18
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i))
			_, err := r.SaveProject(model.Project{ID: "p" + id, Name: "project " + id})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := len(r.ListProjects()); got != n {
		t.Fatalf("concurrent writes lost: got %d want %d", got, n)
	}
	// A missing release cannot be promoted to stable. No bypass of runtime gate.
	if _, err := r.PublishVersion("pa", "client", "stable", "1.0"); err == nil {
		t.Fatal("stable publish unexpectedly succeeded")
	}
}

func TestSQLiteHTTPMutationsCannotReportSuccessWithoutCommit0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "commit-failure.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	// A disk/connection failure after domain mutation must be reported
	// as a durable write or served from the unsynced in-process cache.
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = r.SaveProject(model.Project{ID: "not-committed", Name: "Not committed"})
	if err == nil {
		t.Fatal("success returned for a failed SQLite COMMIT")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("stale unsynced cache remained readable")
			}
		}()
		_, _ = r.GetProject("not-committed")
	}()
	reloaded, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if _, err = reloaded.GetProject("not-committed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("uncommitted project survived restart: %v", err)
	}
}

func TestSQLiteHTTPFilePermissions0372(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.db")
	r, err := OpenSQLiteHTTPRepository0372(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("database readable by group/other: %s", info.Mode().Perm())
	}
}
