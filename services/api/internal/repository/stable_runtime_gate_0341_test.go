package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestStableRepositoryGuardsAndDevContinueWorking0341(t *testing.T) {
	repo := NewMemoryRepository("http://localhost")
	before, err := repo.GetChannelHead(context.Background(), "demo-project", "vanilla", "stable")
	if err != nil {
		t.Fatal(err)
	}
	stable, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.34.1-gate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PublishVersionWithManifestCAS(stable.ProjectID, stable.ProfileID, stable.Channel, stable.Version, stable.Manifest, before.Revision); !errors.Is(err, ErrStableRuntimeGate0341) {
		t.Fatalf("direct stable CAS bypass: %v", err)
	}
	if _, err := repo.UpdateVersionStatus(stable.ProjectID, stable.ID, "published"); !errors.Is(err, ErrStableRuntimeGate0341) {
		t.Fatalf("manual stable status bypass: %v", err)
	}
	after, err := repo.GetChannelHead(context.Background(), "demo-project", "vanilla", "stable")
	if err != nil || after.Revision != before.Revision || after.ReleaseID != before.ReleaseID {
		t.Fatalf("stable head modified: %+v -> %+v, %v", before, after, err)
	}
	for _, channel := range []string{"dev", "test"} {
		release, err := repo.CreateVersion("demo-project", "vanilla", channel, "0.34.1-allowed")
		if err != nil {
			t.Fatal(err)
		}
		published, err := repo.PublishVersionWithManifestCAS(release.ProjectID, release.ProfileID, release.Channel, release.Version, release.Manifest, 0)
		if err != nil || published.Status != "published" {
			t.Fatalf("%s should remain publishable: %+v %v", channel, published, err)
		}
	}
}

func TestStableDurableCommitIsBlockedInRepository0341(t *testing.T) {
	repo := NewMemoryRepository("http://localhost")
	ctx := context.Background()
	release, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.34.1-durable")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(model.DurablePublishPayload{PackageID: release.ID})
	job, _, err := repo.EnqueueDurableJob(ctx, model.DurableJob{Kind: "package-publish", ActorType: "user", ActorID: "admin", Action: "release:publish", ProjectID: release.ProjectID, ResourceType: "package", ResourceID: release.ID, IdempotencyKey: "stable-0341", Payload: raw}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	job, err = repo.LeaseDurableJob(ctx, job.ID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := repo.AcquireDurableScopeLease(ctx, "package:"+release.ID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.CommitDurablePublish(ctx, model.DurablePublishCommit{JobID: job.ID, JobLeaseToken: job.LeaseToken, ScopeKey: lease.ScopeKey, ScopeLeaseToken: lease.LeaseToken, ScopeFencingToken: lease.FencingToken, ExpectedStatus: release.Status})
	if !errors.Is(err, ErrStableRuntimeGate0341) {
		t.Fatalf("durable bypass: %v", err)
	}
	stored, err := repo.GetChannelHead(ctx, "demo-project", "vanilla", "stable")
	if err != nil || stored.Revision != 1 {
		t.Fatalf("stable head moved: %+v %v", stored, err)
	}
}
