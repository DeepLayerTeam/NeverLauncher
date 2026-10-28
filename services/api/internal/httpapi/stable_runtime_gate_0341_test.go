package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestStablePublishRejectsIntegrityAndLegacySignedEvidence0341(t *testing.T) {
	handler, signer := testRuntimeValidationServer0212(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	packageID, digest := createStagedIntegrityPackage0212(t, handler, token, "0.34.1-stable-proof")
	send := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	publish := func() {
		t.Helper()
		rr := send(http.MethodPost, "/api/v1/packages/"+packageID+"/publish", "")
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "stable runtime gate") {
			t.Fatalf("stable must be blocked, got %d %s", rr.Code, rr.Body.String())
		}
	}
	// Explicit project integrity policy is deliberately ineffective for stable.
	rr := send(http.MethodPut, "/api/v1/projects/demo-project/validation-policy", `{"requiredLevel":"integrity"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("set integrity: %d %s", rr.Code, rr.Body.String())
	}
	publish()

	// Even v1 evidence that passes its legacy signature checks is not
	// attestation of a real staged client and a matching server.
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	evidence := runtimeValidationEvidence0212{
		SchemaVersion: runtimeValidationSchema0212, PackageID: packageID,
		ManifestDigest: digest, TargetID: "linux-amd64-java21", RunID: "legacy-v1-stable-0341",
		ActualClient: true, ServerJoin: true, ExitCode: 0,
		EvidenceHashes: map[string]string{"client.log": strings.Repeat("a", 64)},
		StartedAt:      now, FinishedAt: now.Add(30 * time.Second),
	}
	canonical, err := canonicalRuntimeEvidence0212(evidence)
	if err != nil {
		t.Fatal(err)
	}
	submission, _ := json.Marshal(runtimeValidationSubmission0212{
		KeyID: "ci-test", Evidence: evidence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, canonical)),
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/runtime-validations/evidence", bytes.NewReader(submission))
	request.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	if rr.Code != http.StatusCreated {
		t.Fatalf("legacy evidence fixture: %d %s", rr.Code, rr.Body.String())
	}
	publish()

	// Even switching project-wide policy to runtime does not open stable.
	rr = send(http.MethodPut, "/api/v1/projects/demo-project/validation-policy", `{"requiredLevel":"runtime","requireServerJoin":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("set runtime: %d %s", rr.Code, rr.Body.String())
	}
	publish()
	rr = send(http.MethodGet, "/api/v1/packages/"+packageID+"/validations", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"publishEligible":false`) || !strings.Contains(rr.Body.String(), "production-runtime-gate-0.34.11") {
		t.Fatalf("effective stable policy must be visible: %d %s", rr.Code, rr.Body.String())
	}
}

type policyMissing0341 struct{ repository.Repository }

func (p policyMissing0341) GetProjectValidationPolicy(_ context.Context, _ string) (model.ProjectValidationPolicy, error) {
	return model.ProjectValidationPolicy{}, repository.ErrNotFound
}

func TestStableMissingPolicyStillBlocksAndPersistsReason0341(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	srv := Server{Repo: policyMissing0341{repo}}
	release, err := repo.CreateVersion("demo-project", "vanilla", "stable", "missing-policy-0341")
	if err != nil {
		t.Fatal(err)
	}
	err = srv.validatePublishEvidenceContext0213(context.Background(), packageLookup{Release: release})
	if err == nil || !strings.Contains(err.Error(), "stable runtime gate") {
		t.Fatalf("missing policy bypassed stable: %v", err)
	}
	events := repo.ListAuditEvents()
	found := false
	for _, event := range events {
		if event.Target == release.ID && event.ReasonCode == "stable_runtime_targets_incomplete_03411" && event.Action == "release:publish-blocked" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stable denied without durable audit reason: %#v", events)
	}
}
