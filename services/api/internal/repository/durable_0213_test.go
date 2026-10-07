package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestDurableScopeLeaseFencing0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	first, err := r.AcquireDurableScopeLease(ctx, "package:p1", "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := r.RenewDurableScopeLease(ctx, first.ScopeKey, first.LeaseToken, 2*time.Minute)
	if err != nil || renewed.FencingToken != first.FencingToken || !renewed.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("lease renewal changed fence or failed: first=%+v renewed=%+v err=%v", first, renewed, err)
	}
	if _, err := r.AcquireDurableScopeLease(ctx, "package:p1", "worker-b", time.Minute); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("expected lease busy, got %v", err)
	}
	if err := r.ReleaseDurableScopeLease(ctx, first.ScopeKey, first.LeaseToken); err != nil {
		t.Fatal(err)
	}
	second, err := r.AcquireDurableScopeLease(ctx, "package:p1", "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.FencingToken <= first.FencingToken {
		t.Fatalf("fencing token did not increase: first=%d second=%d", first.FencingToken, second.FencingToken)
	}
}

func TestDurableJobIdempotencyRejectsDifferentPayload0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	one, _ := json.Marshal(map[string]any{"packageId": "a"})
	two, _ := json.Marshal(map[string]any{"packageId": "b"})
	base := model.DurableJob{Kind: durableTestKind0213, ActorType: "user", ActorID: "admin", Action: "release:publish", ProjectID: "demo-project", ResourceType: "package", ResourceID: "pkg", IdempotencyKey: "same-key", Payload: one}
	first, created, err := r.EnqueueDurableJob(ctx, base, time.Hour)
	if err != nil || !created {
		t.Fatalf("first enqueue: created=%v err=%v", created, err)
	}
	second, created, err := r.EnqueueDurableJob(ctx, base, time.Hour)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("idempotent enqueue mismatch: created=%v err=%v ids=%s/%s", created, err, first.ID, second.ID)
	}
	base.Payload = two
	if _, _, err := r.EnqueueDurableJob(ctx, base, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestDurableJobIdempotencyIsActorScoped0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	payload, _ := json.Marshal(map[string]any{"packageId": "same-package"})
	base := model.DurableJob{Kind: durableTestKind0213, ActorType: "user", ActorID: "alice", Action: "release:publish", ProjectID: "demo-project", ResourceType: "package", ResourceID: "pkg", IdempotencyKey: "shared-client-key", Payload: payload}
	a, created, err := r.EnqueueDurableJob(ctx, base, time.Hour)
	if err != nil || !created {
		t.Fatalf("alice enqueue: created=%v err=%v", created, err)
	}
	base.ActorID = "bob"
	b, created, err := r.EnqueueDurableJob(ctx, base, time.Hour)
	if err != nil || !created {
		t.Fatalf("bob enqueue with same client key must be isolated: created=%v err=%v", created, err)
	}
	if a.ID == b.ID {
		t.Fatal("different actors received the same durable job")
	}
}

const durableTestKind0213 = "test-publish"

func TestDurablePublishCommitAndOutbox0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	release, err := r.CreateVersion("demo-project", "vanilla", "dev", "0.21.3-test")
	if err != nil {
		t.Fatal(err)
	}
	manifest := release.Manifest
	manifest.Version = release.Version
	manifest.ProjectID = release.ProjectID
	manifest.ProfileID = release.ProfileID
	manifest.Channel = release.Channel
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := r.UpdateVersionManifest(release.ProjectID, release.ID, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := json.Marshal(updated.Manifest)
	manifestSum := sha256.Sum256(manifestRaw)
	manifestDigest := hex.EncodeToString(manifestSum[:])
	artifactSum := sha256.Sum256([]byte("artifact"))
	artifactDigest := hex.EncodeToString(artifactSum[:])
	if _, err := r.SaveIntegrityCheck(ctx, model.IntegrityCheckResult{ID: "int-0213", PackageID: updated.ID, ProjectID: updated.ProjectID, ManifestDigest: manifestDigest, ArtifactDigest: artifactDigest, SignatureVerified: true, StorageVerified: true, FilesVerified: true, CompatibilityVerified: true, Result: "passed", Checks: []map[string]any{{"id": "fixture", "status": "ok"}}, CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(model.DurablePublishPayload{PackageID: updated.ID, ExpectedManifestDigest: manifestDigest, ExpectedArtifactDigest: artifactDigest, ExpectedStatus: updated.Status})
	job, _, err := r.EnqueueDurableJob(ctx, model.DurableJob{Kind: durableTestKind0213, ActorType: "user", ActorID: "admin", Action: "release:publish", ProjectID: updated.ProjectID, ResourceType: "package", ResourceID: updated.ID, IdempotencyKey: "publish-commit", Payload: payload}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	job, err = r.LeaseDurableJob(ctx, job.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireDurableScopeLease(ctx, "package:"+updated.ID, "worker-a:"+job.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	published, err := r.CommitDurablePublish(ctx, model.DurablePublishCommit{JobID: job.ID, JobLeaseToken: job.LeaseToken, ScopeKey: lease.ScopeKey, ScopeLeaseToken: lease.LeaseToken, ScopeFencingToken: lease.FencingToken, ExpectedManifestDigest: manifestDigest, ExpectedArtifactDigest: artifactDigest, ExpectedStatus: updated.Status, ActorID: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if published.Status != "published" {
		t.Fatalf("unexpected release status %q", published.Status)
	}
	stored, err := r.GetDurableJob(ctx, job.ID)
	if err != nil || stored.Status != model.DurableJobStatusSucceeded {
		t.Fatalf("job not completed: %#v err=%v", stored, err)
	}
	outbox, err := r.ClaimOutboxEvents(ctx, "outbox-worker", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbox) != 2 {
		t.Fatalf("expected 2 transactional outbox events, got %d", len(outbox))
	}
	for _, item := range outbox {
		if err := r.CompleteOutboxEvent(ctx, item.ID, item.LeaseToken); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuntimeValidationRunIDIsDurableNonce0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	now := time.Now().UTC()
	base := model.RuntimeValidationResult{ID: "rv-a", PackageID: "pkg-a", ProjectID: "demo-project", ManifestDigest: string(make([]byte, 0)), TargetID: "linux-x64", ActualClient: true, ExitCode: 0, RunID: "gha-run-42", SignerKeyID: "ci-main", SignerKeyFingerprint: hex.EncodeToString(make([]byte, 32)), EvidenceDigest: hex.EncodeToString(make([]byte, 32)), StartedAt: now.Add(-time.Minute), FinishedAt: now, Result: "passed", CreatedAt: now}
	base.ManifestDigest = hex.EncodeToString(make([]byte, 32))
	if _, err := r.SaveRuntimeValidation(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	base.ID = "rv-b"
	base.PackageID = "pkg-b"
	base.TargetID = "windows-x64"
	if _, err := r.SaveRuntimeValidation(context.Background(), base); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected global run nonce conflict, got %v", err)
	}
}

func TestDurablePublishCASRejectsStatusChange0213(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	release, err := r.CreateVersion("demo-project", "vanilla", "dev", "0.21.3-cas-test")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := json.Marshal(release.Manifest)
	manifestSum := sha256.Sum256(manifestRaw)
	manifestDigest := hex.EncodeToString(manifestSum[:])
	artifactSum := sha256.Sum256([]byte("artifact-cas"))
	artifactDigest := hex.EncodeToString(artifactSum[:])
	if _, err := r.SaveIntegrityCheck(ctx, model.IntegrityCheckResult{ID: "int-cas-0213", PackageID: release.ID, ProjectID: release.ProjectID, ManifestDigest: manifestDigest, ArtifactDigest: artifactDigest, SignatureVerified: true, StorageVerified: true, FilesVerified: true, CompatibilityVerified: true, Result: "passed", CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(model.DurablePublishPayload{PackageID: release.ID, ExpectedManifestDigest: manifestDigest, ExpectedArtifactDigest: artifactDigest, ExpectedStatus: release.Status})
	job, _, err := r.EnqueueDurableJob(ctx, model.DurableJob{Kind: durableTestKind0213, ActorType: "user", ActorID: "admin", Action: "release:publish", ProjectID: release.ProjectID, ResourceType: "package", ResourceID: release.ID, IdempotencyKey: "publish-cas-status", Payload: payload}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	job, err = r.LeaseDurableJob(ctx, job.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireDurableScopeLease(ctx, "package:"+release.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.UpdateVersionStatus(release.ProjectID, release.ID, "staged"); err != nil {
		t.Fatal(err)
	}
	_, err = r.CommitDurablePublish(ctx, model.DurablePublishCommit{JobID: job.ID, JobLeaseToken: job.LeaseToken, ScopeKey: lease.ScopeKey, ScopeLeaseToken: lease.LeaseToken, ScopeFencingToken: lease.FencingToken, ExpectedManifestDigest: manifestDigest, ExpectedArtifactDigest: artifactDigest, ExpectedStatus: release.Status, ActorID: "admin"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected status CAS conflict, got %v", err)
	}
}
