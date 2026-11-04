package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func TestSQLiteHTTP0471StrictSnapshot(t *testing.T) {
	raw, err := json.Marshal(snapshotSQLiteHTTP0372(NewMemoryRepository("")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSQLiteHTTPDocument0471(raw); err != nil {
		t.Fatalf("generated snapshot rejected: %v", err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	private := map[string]json.RawMessage{}
	if err = json.Unmarshal(fields["private0373"], &private); err != nil {
		t.Fatal(err)
	}
	delete(private, "passwordHashes")
	incompletePrivate, _ := json.Marshal(private)
	incomplete := bytes.Replace(raw, fieldsOrPrivatePrefix(raw), append([]byte(`"private0373":`), incompletePrivate...), 1)
	delete(fields, "projects")
	missing, _ := json.Marshal(fields)
	for name, document := range map[string][]byte{
		"missing-private-key": incomplete,
		"missing":             missing,
		"unknown":             bytes.Replace(raw, []byte(`"projects":`), []byte(`"alien":1,"projects":`), 1),
		"duplicate":           append([]byte(`{"projects":null,`), raw[1:]...),
		"null-private":        bytes.Replace(raw, fieldsOrPrivatePrefix(raw), []byte(`"private0373":null`), 1),
		"trailing":            append(append([]byte{}, raw...), []byte(` {}`)...),
		"truncated":           raw[:len(raw)-1],
	} {
		if _, err := decodeSQLiteHTTPDocument0471(document); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func fieldsOrPrivatePrefix(raw []byte) []byte {
	// Извлекайте точное исходное значение private0373, включая вложенные массивы.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	return append([]byte(`"private0373":`), fields["private0373"]...)
}

func TestSQLiteHTTP0471RejectsUnrelatedDatabaseAndMissingSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "existing.db")
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		if strings.Contains(err.Error(), "unsupported SQLite filesystem") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, "CREATE TABLE foreign_installation(id INTEGER)")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if r, e := OpenSQLiteHTTPRepository0372(ctx, path, ""); e == nil {
		_ = r.Close()
		t.Fatal("unrelated database initialized as empty launcher")
	}
}

func TestSQLiteHTTP0471HealthVerifiesDocumentAndCache(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	repo, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		if strings.Contains(err.Error(), "unsupported SQLite filesystem") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	defer repo.Close()
	// Документ с корректной контрольной суммой, но несовместимым форматом всё
	// равно нужно отклонить.
	corrupt := []byte(`{"private0373":{}}`)
	sum := sha256.Sum256(corrupt)
	err = repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `UPDATE http_repository_state_0372 SET document=?,sha256=? WHERE singleton=1`, corrupt, hex.EncodeToString(sum[:]))
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Health(ctx); err == nil {
		t.Fatal("invalid document passed readiness")
	}
	if err := repo.Health(ctx); err == nil {
		t.Fatal("repository recovered without a verified reopen")
	}
}
