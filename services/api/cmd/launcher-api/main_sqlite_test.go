package main

import (
	"os"
	"path/filepath"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestSQLiteHTTPRepositoryBootstrap0372(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		RepositoryDriver: "sqlite",
		DatabaseDSN:      filepath.Join(dir, "http-state.db"),
		PublicURL:        "https://launcher.example.test",
	}
	first := newRepository(cfg)
	if _, err := first.SaveProject(model.Project{ID: "installed", Name: "Installed"}); err != nil {
		t.Fatal(err)
	}
	closer, ok := first.(interface{ Close() error })
	if !ok {
		t.Fatal("Backend SQLite не предоставил функцию закрытия постоянного хранилища")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	second := newRepository(cfg)
	defer second.(interface{ Close() error }).Close()
	project, err := second.GetProject("installed")
	if err != nil || project.Name != "Installed" {
		t.Fatalf("Хранилище Backend потеряло данные: %+v / %v", project, err)
	}
}
