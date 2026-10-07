package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/authorization"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestDurablePublishRechecksAuthorizationBeforeCommit0213(t *testing.T) {
	repo := repository.NewMemoryRepository("http://127.0.0.1")
	srv := Server{Repo: repo, Authorization: authorization.New(repo)}
	payload, err := json.Marshal(model.DurablePublishPayload{
		PackageID:              "demo-project-vanilla-3.4.0",
		ExpectedManifestDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedArtifactDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExpectedStatus:         "staged",
	})
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := repo.EnqueueDurableJob(context.Background(), model.DurableJob{
		Kind:           durablePublishJobKind0213,
		ActorType:      "user",
		ActorID:        "admin",
		Action:         "release:publish",
		ProjectID:      "demo-project",
		ResourceType:   "package",
		ResourceID:     "demo-project-vanilla-3.4.0",
		IdempotencyKey: "revoke-during-job",
		Payload:        payload,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := repo.LeaseDurableJob(context.Background(), job.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SetUserDisabled("admin", true); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.executeDurablePublishJob0213(context.Background(), repo, leased, "worker-a"); !errors.Is(err, errDurableAuthorizationRevoked0213) {
		t.Fatalf("expected live authorization revocation, got %v", err)
	}
	stored, err := repo.GetDurableJob(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.DurableJobStatusRevoked {
		t.Fatalf("expected revoked job, got %q", stored.Status)
	}
}
