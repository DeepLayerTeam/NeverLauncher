package repository

import (
	"context"
	"errors"
	"testing"
)

func TestReleaseDraftPersistenceAndCAS0218(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("http://example.test")
	original := ReleaseDraft{ID: "draft-test", ProjectID: "demo-project", OwnerID: "owner-a", Channel: "stable", ProfileID: "vanilla", Version: "1.0.0", Step: "build"}
	created, err := r.CreateReleaseDraft(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.CreatedAt.IsZero() {
		t.Fatalf("not initialized: %+v", created)
	}
	if _, err = r.CreateReleaseDraft(ctx, original); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	rows, err := r.ListReleaseDrafts(ctx, "demo-project", "owner-a")
	if err != nil || len(rows) != 1 {
		t.Fatalf("owner list: %v %#v", err, rows)
	}
	rows, err = r.ListReleaseDrafts(ctx, "demo-project", "owner-b")
	if err != nil || len(rows) != 0 {
		t.Fatalf("Нарушена изоляция владельцев: %v %#v", err, rows)
	}
	update := created
	update.PackageID = "demo-project-vanilla-1.0.0"
	stored, err := r.UpdateReleaseDraft(ctx, update)
	if err != nil || stored.Revision != 2 || stored.PackageID != update.PackageID {
		t.Fatalf("update: %+v %v", stored, err)
	}
	if _, err = r.UpdateReleaseDraft(ctx, update); !errors.Is(err, ErrConflict) {
		t.Fatalf("Обнаружена запись устаревших данных: %v", err)
	}
	hijack := stored
	hijack.OwnerID = "owner-b"
	if _, err = r.UpdateReleaseDraft(ctx, hijack); !errors.Is(err, ErrConflict) {
		t.Fatalf("Передача владения: %v", err)
	}
	if err = r.DeleteReleaseDraft(ctx, stored.ID, "owner-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Удаление чужой записи: %v", err)
	}
	if err = r.DeleteReleaseDraft(ctx, stored.ID, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.GetReleaseDraft(ctx, stored.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Удалённый черновик остаётся видимым: %v", err)
	}
}
