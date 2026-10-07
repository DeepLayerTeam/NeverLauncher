package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestRuntimeValidationPassRequiresActualClient0212(t *testing.T) {
	r := NewMemoryRepository("http://example.test")
	now := time.Now().UTC()
	_, err := r.SaveRuntimeValidation(context.Background(), model.RuntimeValidationResult{
		ID: "rv-1", PackageID: "pkg", ProjectID: "demo-project", ManifestDigest: strings.Repeat("a", 64),
		TargetID: "linux", RunID: "run-no-client", SignerKeyID: "ci", SignerKeyFingerprint: strings.Repeat("d", 64), EvidenceDigest: strings.Repeat("b", 64),
		StartedAt: now.Add(-time.Second), FinishedAt: now, Result: "passed", ActualClient: false,
	})
	if err == nil {
		t.Fatal("runtime PASS without actual client must fail closed")
	}
}

func TestRuntimeValidationPassRequiresZeroExitCode0212(t *testing.T) {
	r := NewMemoryRepository("http://example.test")
	now := time.Now().UTC()
	_, err := r.SaveRuntimeValidation(context.Background(), model.RuntimeValidationResult{
		ID: "rv-exit", PackageID: "pkg", ProjectID: "demo-project", ManifestDigest: strings.Repeat("a", 64),
		TargetID: "linux", RunID: "run-exit", SignerKeyID: "ci", SignerKeyFingerprint: strings.Repeat("d", 64), EvidenceDigest: strings.Repeat("b", 64),
		StartedAt: now.Add(-time.Second), FinishedAt: now, Result: "passed", ActualClient: true, ExitCode: 1,
	})
	if err == nil {
		t.Fatal("runtime PASS with non-zero exit code must fail closed")
	}
}

func TestRuntimeValidationDuplicateRunTargetRejected0212(t *testing.T) {
	r := NewMemoryRepository("http://example.test")
	now := time.Now().UTC()
	base := model.RuntimeValidationResult{
		ID: "rv-1", PackageID: "pkg", ProjectID: "demo-project", ManifestDigest: strings.Repeat("a", 64),
		TargetID: "linux", RunID: "run-1", SignerKeyID: "ci", SignerKeyFingerprint: strings.Repeat("d", 64), EvidenceDigest: strings.Repeat("b", 64),
		StartedAt: now.Add(-time.Second), FinishedAt: now, Result: "passed", ActualClient: true,
	}
	if _, err := r.SaveRuntimeValidation(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	base.ID = "rv-2"
	base.EvidenceDigest = strings.Repeat("c", 64)
	if _, err := r.SaveRuntimeValidation(context.Background(), base); err != ErrConflict {
		t.Fatalf("duplicate run/target must return ErrConflict, got %v", err)
	}
}

func TestProjectValidationPolicyNormalizesAndPersists0212(t *testing.T) {
	r := NewMemoryRepository("http://example.test")
	p, err := r.SaveProjectValidationPolicy(context.Background(), model.ProjectValidationPolicy{ProjectID: "demo-project", RequiredLevel: "RUNTIME", RequireServerJoin: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.RequiredLevel != "runtime" || !p.RequireServerJoin {
		t.Fatalf("unexpected policy: %#v", p)
	}
	stored, err := r.GetProjectValidationPolicy(context.Background(), "demo-project")
	if err != nil || stored.RequiredLevel != "runtime" || !stored.RequireServerJoin {
		t.Fatalf("stored policy mismatch: %#v err=%v", stored, err)
	}
}
