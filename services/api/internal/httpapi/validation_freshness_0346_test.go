package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func testTarget0346(p validationPayload0345) validationTarget0346 {
	return validationTarget0346{ID: p.TargetID, ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion, ManifestSHA256: p.ManifestSHA256, ArtifactSHA256: p.ArtifactSHA256, ResolvedPlanSHA256: p.ResolvedPlanSHA256, SourceSHA: p.SourceSHA, BuildSHA: p.BuildSHA, JavaSHA256: p.JavaSHA256, JavaVersion: p.JavaVersion, OS: p.OS, Arch: p.Arch, Loader: p.Loader, InstallAdapterSHA256: p.InstallAdapterSHA256, GuardMode: p.GuardMode, GuardPolicySHA256: p.GuardPolicySHA256, ServerBridgeSHA256: p.ServerBridgeSHA256, ServerPluginVersion: p.ServerPluginVersion, Preset: p.Preset, AuthenticationMode: p.AuthenticationMode}
}
func TestV05ExactSignedTargetApplicability0346(t *testing.T) {
	signed, priv, pub := validValidationFixture0345(t)
	p := signed.Evidence
	release := model.ReleaseVersion{ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion}
	target := testTarget0346(p)
	raw, _ := json.Marshal([]validationTarget0346{target})
	got, matrix, err := configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256)
	if err != nil || len(got) != 1 || !matchingTarget0346(p, got[0]) || matrix == "" {
		t.Fatalf("valid pinned target rejected: %v", err)
	}
	p.TargetMatrixSHA256 = matrix
	for name, mutate := range map[string]func(*validationPayload0345){
		"release-version": func(p *validationPayload0345) { p.PackageVersion = "0.34.5" },
		"java-binary":     func(p *validationPayload0345) { p.JavaSHA256 = strings.Repeat("8", 64) },
		"java-version":    func(p *validationPayload0345) { p.JavaVersion = "17.0.9" },
		"preset":          func(p *validationPayload0345) { p.Preset = "optional" },
		"server-plugin":   func(p *validationPayload0345) { p.ServerPluginVersion = "other" },
		"auth-mode":       func(p *validationPayload0345) { p.AuthenticationMode = "custom" },
		"adapter":         func(p *validationPayload0345) { p.InstallAdapterSHA256 = strings.Repeat("9", 64) },
		"guard-policy":    func(p *validationPayload0345) { p.GuardPolicySHA256 = strings.Repeat("f", 64) },
		"resolved-plan":   func(p *validationPayload0345) { p.ResolvedPlanSHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			signed.Evidence = changed
			signFixture0345(t, &signed, priv)
			if !matchingTarget0346(changed, target) && verifyValidation0345(signed, pub) == nil {
				return
			}
			t.Fatalf("wrong target accepted or signature failed unexpectedly")
		})
	}
	other := target
	other.JavaSHA256 = strings.Repeat("8", 64)
	other.ID = "second"
	raw, _ = json.Marshal([]validationTarget0346{target, other})
	targets, matrix2, err := configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256)
	if err != nil || len(targets) != 2 || matrix2 == matrix {
		t.Fatalf("target matrix did not invalidate after adding required target: %v", err)
	}
	other.ManifestSHA256 = strings.Repeat("0", 64)
	raw, _ = json.Marshal([]validationTarget0346{target, other})
	if _, _, err = configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256); err == nil {
		t.Fatal("inconsistent snapshots accepted")
	}
}
func TestV05RunNonceExpiryReplayAndRevocation0346(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	p := signed.Evidence
	r := repository.NewMemoryRepository("https://example.test")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p.IssuedAt = now.Add(-4 * time.Minute).Format(time.RFC3339Nano)
	p.ExpiresAt = now.Add(20 * time.Hour).Format(time.RFC3339Nano)
	p.StartedAt = now.Add(-3 * time.Minute).Format(time.RFC3339Nano)
	p.FinishedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	challenge := model.ValidationChallenge0346{RunID: p.RunID, Nonce: p.RunNonce, PackageID: p.PackageID, ManifestSHA256: p.ManifestSHA256, ArtifactSHA256: p.ArtifactSHA256, TargetMatrixSHA256: p.TargetMatrixSHA256, IssuedAt: now.Add(-4 * time.Minute), ExpiresAt: now.Add(30 * time.Minute)}
	if err := r.SaveValidationChallenge0346(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if err := validateFreshness0346(ctx, r, p, now, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveValidationChallenge0346(ctx, challenge); err == nil {
		t.Fatal("run nonce replay accepted")
	}
	changed := p
	changed.RunNonce = strings.Repeat("0", 64)
	if validateFreshness0346(ctx, r, changed, now, true) == nil {
		t.Fatal("different run nonce accepted")
	}
	changed = p
	changed.PackageID = "another"
	if validateFreshness0346(ctx, r, changed, now, true) == nil {
		t.Fatal("wrong package accepted")
	}
	changed = p
	changed.TargetMatrixSHA256 = strings.Repeat("e", 64)
	if validateFreshness0346(ctx, r, changed, now, true) == nil {
		t.Fatal("wrong target policy accepted")
	}
	changed = p
	changed.Audience = "another"
	if validateFreshness0346(ctx, r, changed, now, true) == nil {
		t.Fatal("wrong purpose/audience accepted")
	}
	changed = p
	changed.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	if validateFreshness0346(ctx, r, changed, now, true) == nil {
		t.Fatal("expired evidence accepted")
	}
	if validateFreshness0346(ctx, r, p, now.Add(31*time.Minute), true) == nil {
		t.Fatal("expired challenge accepted for new attestation")
	}
	if err := validateFreshness0346(ctx, r, p, now.Add(31*time.Minute), false); err != nil {
		t.Fatalf("previously accepted evidence cannot survive grant expiration: %v", err)
	}
	if err := r.RevokeValidationKey0346(ctx, p.SignerKeyID, "operator", "suspected compromise"); err != nil {
		t.Fatal(err)
	}
	if validateFreshness0346(ctx, r, p, now, false) == nil {
		t.Fatal("revoked key accepted")
	}
}
