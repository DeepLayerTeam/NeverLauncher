package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func TestHTTPUpgrade0472PreservesProjectAndPrivateAuth(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "http.sqlite")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://test.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.SaveProject(model.Project{ID: "preserved", Name: "Old project"}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.SaveUser(model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner", Status: "active", PasswordHash: "verifier-secret"}); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		var raw []byte
		if e := q.QueryRowContext(ctx, "SELECT document FROM http_repository_state_0372 WHERE singleton=1").Scan(&raw); e != nil {
			return e
		}
		var snapshot map[string]json.RawMessage
		if e := json.Unmarshal(raw, &snapshot); e != nil {
			return e
		}
		delete(snapshot, "extensionEmergencyDisables")
		updated, e := json.Marshal(snapshot)
		if e != nil {
			return e
		}
		sha := sha256.Sum256(updated)
		if _, e = q.ExecContext(ctx, "UPDATE http_repository_state_0372 SET document=?,sha256=? WHERE singleton=1", updated, hex.EncodeToString(sha[:])); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "DROP INDEX http_stable_permits_package_0374"); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "DROP TABLE http_runtime_components_0373")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, path, "https://test.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ListProjects()) != 1 || r.ListProjects()[0].ID != "preserved" {
		t.Fatal("Проект потерян")
	}
	if len(r.mem.users) != 1 || r.mem.users[0].PasswordHash != "verifier-secret" {
		t.Fatal("Данные приватной аутентификации потеряны")
	}
	if err = r.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	backup, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if len(backup) != 1 {
		t.Fatalf("Отсутствует проверенная резервная копия: %v", backup)
	}
	if _, err = sqlitedurable.VerifyBackup(ctx, backup[0]); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, path, "https://test.example")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	backups, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if len(backups) != 1 {
		t.Fatal("Обновление не идемпотентно")
	}
}

func TestHTTPUpgrade0472RejectsMissingAuthSecretsWithoutMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "http.sqlite")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.SaveUser(model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner", Status: "active", PasswordHash: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		var raw []byte
		if e := q.QueryRowContext(ctx, "SELECT document FROM http_repository_state_0372").Scan(&raw); e != nil {
			return e
		}
		var v map[string]json.RawMessage
		if e := json.Unmarshal(raw, &v); e != nil {
			return e
		}
		delete(v, "private0373")
		updated, e := json.Marshal(v)
		if e != nil {
			return e
		}
		sha := sha256.Sum256(updated)
		if _, e = q.ExecContext(ctx, "UPDATE http_repository_state_0372 SET document=?,sha256=?", updated, hex.EncodeToString(sha[:])); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "DROP TABLE http_runtime_components_0373")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if r, err = OpenSQLiteHTTPRepository0372(ctx, path, ""); err == nil {
		_ = r.Close()
		t.Fatal("Ошибочно принято отсутствие секретов")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "pre-upgrade-backups")); !os.IsNotExist(err) {
		t.Fatalf("Неожиданная резервная копия или файл: %v", err)
	}
}
