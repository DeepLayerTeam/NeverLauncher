package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestMigrationTargetSteps0331(t *testing.T) {
	repo := repository.NewMemoryRepository("")
	project, err := repo.SaveProject(model.Project{ID: "migration-target", Name: "Migration target"})
	if err != nil {
		t.Fatal(err)
	}
	server := Server{Repo: repo}
	for _, step := range []string{"target_check", "target_inventory"} {
		result, err := server.migrationBaseline0331(context.Background(), mw.Run{ProjectID: project.ID, Step: step})
		if err != nil || !json.Valid(result) {
			t.Fatalf("step %s: %s %v", step, result, err)
		}
	}
	if _, err = server.migrationBaseline0331(context.Background(), mw.Run{ProjectID: project.ID, Step: "cutover"}); err == nil {
		t.Fatal("unsafe cutover treated as executable")
	}
}
