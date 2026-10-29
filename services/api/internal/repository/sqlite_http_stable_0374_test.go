package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type stableSQLiteFixture0374 struct {
	repo     *SQLiteHTTPRepository0372
	path     string
	rel      model.ReleaseVersion
	commit   model.DurablePublishCommit
	permit   StableRuntimePermit03411
	evidence sqliteSignedEvidence0374
	key      ed25519.PrivateKey
}

func stableFixture0374(t *testing.T) stableSQLiteFixture0374 {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "stable.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err = r.SaveProject(model.Project{ID: "project-stable", Name: "Stable"}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.SaveProfile(model.Profile{ID: "vanilla", ProjectID: "project-stable", Name: "Vanilla", Loader: "vanilla"}); err != nil {
		t.Fatal(err)
	}
	rel, err := r.CreateVersion("project-stable", "vanilla", "stable", "0.37.4")
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(rel.Manifest)
	h := sha256.Sum256(manifest)
	md := hex.EncodeToString(h[:])
	ad := strings.Repeat("b", 64)
	matrix := strings.Repeat("c", 64)
	if _, err = r.SaveIntegrityCheck(ctx, model.IntegrityCheckResult{ID: "check-1", ProjectID: rel.ProjectID, PackageID: rel.ID, ManifestDigest: md, ArtifactDigest: ad, Result: "passed"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"packageId": rel.ID})
	job, created, err := r.EnqueueDurableJob(ctx, model.DurableJob{Kind: "package-publish", ActorType: "user", ActorID: "owner", Action: "release:publish", ProjectID: rel.ProjectID, ResourceType: "package", ResourceID: rel.ID, IdempotencyKey: "request-1", Payload: raw}, time.Hour)
	if err != nil || !created {
		t.Fatalf("job: %v", err)
	}
	job, err = r.LeaseDurableJob(ctx, job.ID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.AcquireDurableScopeLease(ctx, "package:"+rel.ID, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rev := int64(0)
	commit := model.DurablePublishCommit{JobID: job.ID, JobLeaseToken: job.LeaseToken, ScopeKey: lease.ScopeKey, ScopeLeaseToken: lease.LeaseToken, ScopeFencingToken: lease.FencingToken, ExpectedStatus: rel.Status, ExpectedManifestDigest: md, ExpectedArtifactDigest: ad, ExpectedHeadRevision: &rev, ActorID: "owner"}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(pub)
	now := time.Now().UTC()
	target := map[string]string{"id": "linux-x64", "projectId": rel.ProjectID, "profileId": "vanilla", "channel": "stable", "manifestSha256": md, "artifactSha256": ad, "version": rel.Version, "resolvedPlanSha256": strings.Repeat("1", 64), "sourceSha": strings.Repeat("2", 40), "buildSha": strings.Repeat("3", 64), "javaSha256": strings.Repeat("4", 64), "javaVersion": "21", "os": "linux", "arch": "amd64", "loader": "vanilla", "installAdapterSha256": strings.Repeat("5", 64), "guardMode": "strict", "guardPolicySha256": strings.Repeat("6", 64), "serverBridgeSha256": strings.Repeat("7", 64), "serverPluginVersion": "1.0", "preset": "default", "authenticationMode": "custom"}
	targets, _ := json.Marshal([]map[string]string{target})
	p := StableRuntimePermit03411{PackageID: rel.ID, ProjectID: rel.ProjectID, ManifestSHA256: md, ArtifactSHA256: ad, MatrixSHA256: matrix, TargetsJSON: targets, Runs: map[string]string{"linux-x64": "run-1"}, TrustedAttestorKey0374: base64.RawURLEncoding.EncodeToString(pub)}
	ev := sqliteSignedEvidence0374{SchemaVersion: "neverlauncher.validation-evidence.v4", RunNonce: strings.Repeat("8", 64), Audience: "neverlauncher-api/validation-evidence/0.34.7", Purpose: "staged-package-runtime-verification", TargetID: target["id"], TargetMatrixSHA256: matrix, SignerKeyID: hex.EncodeToString(fingerprint[:]), PackageVersion: rel.Version, RunID: "run-1", PackageID: rel.ID, ManifestSHA256: md, ArtifactSHA256: ad, ResolvedPlanSHA256: target["resolvedPlanSha256"], SourceSHA: target["sourceSha"], BuildSHA: target["buildSha"], RunnerImageSHA256: strings.Repeat("9", 64), JavaSHA256: target["javaSha256"], JavaVersion: target["javaVersion"], OS: target["os"], Arch: target["arch"], Loader: target["loader"], InstallAdapterSHA256: target["installAdapterSha256"], GuardMode: target["guardMode"], GuardPolicySHA256: target["guardPolicySha256"], ServerBridgeSHA256: target["serverBridgeSha256"], ServerPluginVersion: target["serverPluginVersion"], Preset: target["preset"], AuthenticationMode: target["authenticationMode"], Stages: map[string]string{}, ArtifactHashes: map[string]string{"verified.json": strings.Repeat("a", 64)}, StartedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), FinishedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	for _, stage := range requiredStableStages0374 {
		ev.Stages[stage] = "passed"
	}
	for _, file := range []string{"staged-execution.json", "verified.json", "startup-readiness.json", "server-readiness.json", "gameplay-smoke.json", "authentication.json", "runtime-launch.json", "runtime-gameplay-launch.json", "execution-identity.json", "update-recovery.json"} {
		ev.ArtifactHashes[file] = strings.Repeat("a", 64)
	}
	return stableSQLiteFixture0374{repo: r, path: path, rel: rel, commit: commit, permit: p, evidence: ev, key: priv}
}

func (f *stableSQLiteFixture0374) installEvidence(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := f.repo.SaveValidationChallenge0346(ctx, model.ValidationChallenge0346{RunID: f.evidence.RunID, Nonce: f.evidence.RunNonce, PackageID: f.rel.ID, ProjectID: f.rel.ProjectID, ManifestSHA256: f.permit.ManifestSHA256, ArtifactSHA256: f.permit.ArtifactSHA256, TargetMatrixSHA256: f.permit.MatrixSHA256, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	stageMap := map[string]map[string]string{}
	for _, stage := range requiredStableStages0374 {
		v := map[string]string{"status": "passed"}
		if name := stableStageArtifacts0374[stage]; name != "" {
			v["evidenceSha256"] = f.evidence.ArtifactHashes[name]
		}
		stageMap[stage] = v
	}
	stepsRaw, _ := json.Marshal(stageMap)
	started, _ := time.Parse(time.RFC3339Nano, f.evidence.StartedAt)
	finished, _ := time.Parse(time.RFC3339Nano, f.evidence.FinishedAt)
	report := model.StagedRuntimeRun0342{RunID: f.evidence.RunID, PackageID: f.rel.ID, ProjectID: f.rel.ProjectID, ManifestSHA256: f.permit.ManifestSHA256, ArtifactSHA256: f.permit.ArtifactSHA256, Stages: stepsRaw, StartedAt: started, FinishedAt: finished, ReceivedAt: now}
	if err := f.repo.SaveStagedRun0342(ctx, report); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(f.key, append([]byte("NeverLauncher/validation-evidence/v4\x00"), raw...))
	if err = f.repo.SaveValidationAttestation0345(ctx, model.ValidationAttestation0345{RunID: f.evidence.RunID, PackageID: f.rel.ID, ProjectID: f.rel.ProjectID, ManifestSHA256: f.permit.ManifestSHA256, ArtifactSHA256: f.permit.ArtifactSHA256, Evidence: raw, Signature: base64.RawURLEncoding.EncodeToString(sig), ReceivedAt: now}); err != nil {
		t.Fatal(err)
	}
}
func (f *stableSQLiteFixture0374) issue(t *testing.T) string {
	t.Helper()
	token, err := f.repo.IssueStableRuntimePermit03411(context.Background(), f.permit)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSQLiteStablePublishAtomicReplayAndRestart0374(t *testing.T) {
	f := stableFixture0374(t)
	ctx := context.Background()
	if _, err := f.repo.CommitDurablePublish(ctx, f.commit); !errors.Is(err, ErrStableRuntimeGate0341) {
		t.Fatalf("no grant: %v", err)
	}
	head, err := f.repo.GetChannelHead(ctx, f.rel.ProjectID, f.rel.ProfileID, "stable")
	if err != nil || head.Revision != 0 {
		t.Fatalf("uncertified head changed: %+v %v", head, err)
	}
	f.installEvidence(t)
	token := f.issue(t)
	f.commit.StableGateToken03411 = token
	published, err := f.repo.CommitDurablePublish(ctx, f.commit)
	if err != nil || published.Status != "published" {
		t.Fatalf("verified stable publish: %+v %v", published, err)
	}
	if _, err = f.repo.CommitDurablePublish(ctx, f.commit); err == nil {
		t.Fatal("replayed publish")
	}
	head, err = f.repo.GetChannelHead(ctx, f.rel.ProjectID, f.rel.ProfileID, "stable")
	if err != nil || head.Revision != 1 || head.ReleaseID != f.rel.ID {
		t.Fatalf("head: %+v %v", head, err)
	}
	if err = f.repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteHTTPRepository0372(ctx, f.path, "")
	if err != nil {
		t.Fatal(err)
	}
	f.repo = reopened
	head, err = reopened.GetChannelHead(ctx, f.rel.ProjectID, f.rel.ProfileID, "stable")
	if err != nil || head.Revision != 1 {
		t.Fatalf("stable lost on restart: %+v %v", head, err)
	}
	job, err := reopened.GetDurableJob(ctx, f.commit.JobID)
	if err != nil || job.Status != model.DurableJobStatusSucceeded {
		t.Fatalf("job lost: %+v %v", job, err)
	}
	outbox, err := reopened.ClaimOutboxEvents(ctx, "worker", 10, time.Minute)
	if err != nil || len(outbox) != 2 {
		t.Fatalf("outbox not atomically saved: %+v %v", outbox, err)
	}
	if _, err = reopened.CommitDurablePublish(ctx, f.commit); err == nil {
		t.Fatal("spent grant reused after process restart")
	}
}
func TestSQLiteStablePublishRevocationForgeryAndExpiration0374(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []string{"no-evidence", "bad-signature", "revoked", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := stableFixture0374(t)
			if scenario != "no-evidence" {
				f.installEvidence(t)
			}
			if scenario == "bad-signature" {
				f.repo.mu.Lock()
				f.repo.mem.validationAttestations0345[0].Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				f.repo.mu.Unlock()
			}
			token := f.issue(t)
			f.commit.StableGateToken03411 = token
			if scenario == "revoked" {
				if err := f.repo.RevokeValidationKey0346(ctx, f.evidence.SignerKeyID, "owner", "compromised"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "expired" {
				h := sha256.Sum256([]byte(token))
				err := f.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
					_, err := q.ExecContext(ctx, `UPDATE http_stable_permits_0374 SET expires_at=? WHERE token_sha256=?`, time.Now().UTC().Add(-time.Second).UnixNano(), hex.EncodeToString(h[:]))
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.repo.CommitDurablePublish(ctx, f.commit); !errors.Is(err, ErrStableRuntimeGate0341) {
				t.Fatalf("%s accepted: %v", scenario, err)
			}
			head, err := f.repo.GetChannelHead(ctx, f.rel.ProjectID, f.rel.ProfileID, "stable")
			if err != nil || head.Revision != 0 {
				t.Fatalf("rejected operation moved head: %+v %v", head, err)
			}
		})
	}
}
func TestSQLiteStablePublishConcurrentSingleCommit0374(t *testing.T) {
	f := stableFixture0374(t)
	f.installEvidence(t)
	f.commit.StableGateToken03411 = f.issue(t)
	const attempts = 8
	var wg sync.WaitGroup
	successes := make(chan bool, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.repo.CommitDurablePublish(context.Background(), f.commit)
			successes <- err == nil
		}()
	}
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent stable publication accepted %d requests", count)
	}
}
