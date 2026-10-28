package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestV07FailClosedRealProviderAttestation(t *testing.T) {
	signed, private, public := validValidationFixture0345(t)
	if signed.Evidence.AuthenticationMode != "official" {
		t.Fatal("fixture requires real official authentication mode")
	}
	if err := verifyValidation0345(signed, public); err != nil {
		t.Fatal(err)
	}
	// A correctly signed mock, skipped, inconclusive or missing provider
	// result must not certify the staged runtime.
	for _, status := range []string{"mock", "inconclusive", "blocked", "failed", "skipped", ""} {
		t.Run("stage-"+status, func(t *testing.T) {
			changed := signed
			changed.Evidence.Stages = make(map[string]string, len(signed.Evidence.Stages))
			for k, v := range signed.Evidence.Stages {
				changed.Evidence.Stages[k] = v
			}
			changed.Evidence.Stages["authentication"] = status
			signFixture0345(t, &changed, private)
			if err := verifyValidation0345(changed, public); err == nil {
				t.Fatal("synthetic or inconclusive authentication certified")
			}
		})
	}
	for _, mode := range []string{"", "mock", "offline", "none"} {
		changed := signed
		changed.Evidence.AuthenticationMode = mode
		signFixture0345(t, &changed, private)
		if err := verifyValidation0345(changed, public); err == nil {
			t.Fatalf("forbidden authentication mode %q accepted", mode)
		}
	}
	other := signed
	other.Evidence.AuthenticationMode = "custom"
	signFixture0345(t, &other, private)
	if err := verifyValidation0345(other, public); err != nil {
		t.Fatal(err)
	}
	if matchingTarget0346(other.Evidence, testTarget0346(signed.Evidence)) {
		t.Fatal("valid signature for different provider inherited official target")
	}
}

func TestV07MissingAuthTargetAndAuthStageRejected(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	release := model.ReleaseVersion{ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: signed.Evidence.PackageVersion}
	target := testTarget0346(signed.Evidence)
	target.AuthenticationMode = ""
	blob, _ := json.Marshal([]validationTarget0346{target})
	if _, _, err := configuredTargets0346(string(blob), release, signed.Evidence.ManifestSHA256, signed.Evidence.ArtifactSHA256); err == nil {
		t.Fatal("target missing provider mode accepted")
	}
	now := time.Now().UTC()
	grant := stagedGrant0342{Schema: stagedGrantSchema0342, PackageID: signed.Evidence.PackageID,
		RunID: signed.Evidence.RunID, ManifestSHA256: signed.Evidence.ManifestSHA256,
		ArtifactSHA256: signed.Evidence.ArtifactSHA256, ExpiresAt: now.Add(time.Hour).Unix()}
	report := stagedRunReport0342{Schema: stagedRunSchema0342, PackageID: grant.PackageID,
		RunID: grant.RunID, ManifestSHA256: grant.ManifestSHA256, ArtifactSHA256: grant.ArtifactSHA256,
		StartedAt: now.Add(-time.Minute), FinishedAt: now,
		Stages: map[string]stagedStep0342{"authentication": {Status: "inconclusive", Detail: "provider outage"}}}
	if err := validateStagedRunReport0342(grant, report); err != nil {
		t.Fatalf("provider outage diagnostic rejected: %v", err)
	}
	report.Stages["authentication"] = stagedStep0342{Status: "passed", EvidenceSHA256: strings.Repeat("a", 64)}
	if err := validateStagedRunReport0342(grant, report); err != nil {
		t.Fatalf("auth stage digest diagnostic rejected: %v", err)
	}
	// Untrusted staged report never directly certifies a release; only the
	// separately pinned attestor's v4 evidence can enter the trust store.
}
