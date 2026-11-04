package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestV12ForgedExpiredUnsignedManualCertification03412(t *testing.T) {
	signed, _, trusted := validValidationFixture0345(t)
	if err := verifyValidation0345(signed, trusted); err != nil {
		t.Fatal(err)
	}
	// Forged signatures, missing proof, malicious JSON and stale evidence cannot
	// be promoted by uploading a status flag or copying an old run.
	signed.Signature = ""
	if verifyValidation0345(signed, trusted) == nil {
		t.Fatal("unsigned runner accepted")
	}
	signed, _, trusted = validValidationFixture0345(t)
	raw, _ := json.Marshal(signed.Evidence)
	raw = append(raw[:len(raw)-1], []byte(`,"certified":true}`)...)
	var out validationPayload0345
	if decodeStoredEvidence03411(raw, &out) == nil {
		t.Fatal("manual certified field admitted")
	}
	signed.Evidence.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	repo := repository.NewMemoryRepository("https://example.test")
	if err := validateFreshness0346(context.Background(), repo, signed.Evidence, time.Now(), false); err == nil {
		t.Fatal("expired evidence accepted")
	}
	if strings.Contains(redactValidationDetail03412("Authorization: Bearer AAAAA access_token=BBBBB"), "BBBBB") {
		t.Fatal("secret leaked")
	}
}
func TestV12GateFailedAttemptHasImmutableDigest03412(t *testing.T) {
	repo := repository.NewMemoryRepository("https://example.test")
	release, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.34.12")
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Repo: repo}
	if _, _, err = s.issueStablePermit03411(context.Background(), packageLookup{Release: release}); err == nil {
		t.Fatal("missing certified targets allowed stable")
	}
	events, err := repo.ListValidationAttempts03412(context.Background(), release.ID, 0, 10)
	if err != nil || len(events) != 1 || events[0].Kind != "stable-gate" || events[0].Outcome != "blocked" || len(events[0].PayloadSHA256) != 64 {
		t.Fatalf("denied publish not audited: %+v %v", events, err)
	}
}
