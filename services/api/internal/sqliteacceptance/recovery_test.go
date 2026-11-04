package sqliteacceptance

// Аварийно завершите весь процесс сервиса с тремя открытыми SQLite-хранилищами.
// Следующий процесс обязан восстановить зафиксированные WAL-кадры, а не считать их
// устаревшими sidecar-файлами или молча создавать пустое состояние проекта и
// координатора.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecoord"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func TestThreeDatabasesRecoverCommittedStateAfterAbruptExit0471(t *testing.T) {
	root := os.Getenv("LAUNCHER_SQLITE_TEST_ROOT")
	if root == "" {
		root = t.TempDir()
	} else {
		var err error
		root, err = os.MkdirTemp(root, "crash-0471-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	probe, err := sqlitedurable.Open(context.Background(), sqlitedurable.Options{Path: filepath.Join(root, "fs-probe.db")})
	if err != nil {
		if strings.Contains(err.Error(), "unsupported SQLite filesystem") && os.Getenv("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1" {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestThreeDatabaseChild0471$")
	child.Env = append(os.Environ(), "LAUNCHER_0471_CRASH_ROOT="+root)
	if output, err := child.CombinedOutput(); err == nil {
		t.Fatalf("child did not crash: %s", output)
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 71 {
		t.Fatalf("child crash unexpected: %v: %s", err, output)
	}
	ctx := context.Background()
	httpRepo, err := repository.OpenSQLiteHTTPRepository0372(ctx, filepath.Join(root, "http.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer httpRepo.Close()
	if _, err = httpRepo.GetProject("project-before-crash"); err != nil {
		t.Fatalf("HTTP lost WAL commit: %v", err)
	}
	if err = httpRepo.Health(ctx); err != nil {
		t.Fatal(err)
	}
	core, err := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: filepath.Join(root, "core.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if _, err = core.GetProject(ctx, "core-project"); err != nil {
		t.Fatalf("Core lost WAL commit: %v", err)
	}
	coord, err := sqlitecoord.Open(ctx, filepath.Join(root, "coordinator.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer coord.Close()
	r, err := coord.Allow(ctx, "crash-client", 1, time.Hour)
	if err != nil || r.Allowed {
		t.Fatalf("rate limiter lost acknowledged event: %+v %v", r, err)
	}
}

func TestThreeDatabaseChild0471(t *testing.T) {
	root := os.Getenv("LAUNCHER_0471_CRASH_ROOT")
	if root == "" {
		return
	}
	ctx := context.Background()
	httpRepo, err := repository.OpenSQLiteHTTPRepository0372(ctx, filepath.Join(root, "http.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = httpRepo.SaveProject(model.Project{ID: "project-before-crash", Name: "Durable"}); err != nil {
		t.Fatal(err)
	}
	core, err := sqlitecore.Open(ctx, sqlitedurable.Options{Path: filepath.Join(root, "core.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.SaveProject(ctx, model.Project{ID: "core-project", Name: "Durable Core"}, "operator"); err != nil {
		t.Fatal(err)
	}
	coord, err := sqlitecoord.Open(ctx, filepath.Join(root, "coordinator.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := coord.Allow(ctx, "crash-client", 1, time.Hour)
	if err != nil || !allowed.Allowed {
		t.Fatalf("first grant: %+v %v", allowed, err)
	}
	// Без Close, WAL-checkpoint и очистки уровня процесса.
	os.Exit(71)
}
