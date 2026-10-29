package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublishReadiness0385ExplainsBrokenPackageAndBlocksPreview(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	created := send("POST", "/api/v1/packages", `{"projectId":"demo-project","profileId":"vanilla","channel":"dev","version":"0385-broken"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var payload struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if e := json.Unmarshal(created.Body.Bytes(), &payload); e != nil {
		t.Fatal(e)
	}
	id := payload.Data.PackageID
	read := send("GET", "/api/v1/packages/"+id+"/validations", "")
	if read.Code != http.StatusOK {
		t.Fatalf("read: %d %s", read.Code, read.Body.String())
	}
	var response struct {
		Data struct {
			PublishReadiness publishReadiness0385 `json:"publishReadiness"`
		} `json:"data"`
	}
	if e := json.Unmarshal(read.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	r := response.Data.PublishReadiness
	if r.Eligible || !r.FinalRecheckRequired {
		t.Fatalf("empty package wrongly eligible: %+v", r)
	}
	foundFiles, foundSignature := false, false
	for _, b := range r.Blockers {
		if b.ReasonCode == "package-files-empty" {
			foundFiles = true
		}
		if b.ReasonCode == "manifest-signature-invalid" {
			foundSignature = true
		}
		if b.Resource == "" || b.Message == "" || b.Action == "" {
			t.Fatalf("incomplete blocker: %+v", b)
		}
	}
	if !foundFiles || !foundSignature {
		t.Fatalf("missing useful blockers: %+v", r.Blockers)
	}
	body := `{"kind":"package-publish","projectId":"demo-project","profileId":"vanilla","resourceId":"` + id + `","channel":"dev","idempotencyKey":"0385-refusal"}`
	for _, path := range []string{"/api/v1/operations/validate", "/api/v1/operations/execute"} {
		rec := send("POST", path, body)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"reasonCode":"publish-blocked"`) || !strings.Contains(rec.Body.String(), `"package-files-empty"`) {
			t.Fatalf("broken package allowed %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestPublishRefusal0385KeepsIndividualTargetReasons(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOperationError0217(rec, publishBlocked0385{Blockers: []publishBlocker0385{{"stable-runtime-target-blocked", "linux-amd64", "missing attestation", "Run real target"}}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d", rec.Code)
	}
	var result struct {
		Error struct {
			ReasonCode string               `json:"reasonCode"`
			Blockers   []publishBlocker0385 `json:"blockers"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error.ReasonCode != "publish-blocked" || len(result.Error.Blockers) != 1 || result.Error.Blockers[0].Resource != "linux-amd64" {
		t.Fatalf("lost targets: %+v", result)
	}
}

func TestStableReadiness0385RequiresIndependentRuntimeEvidence(t *testing.T) {
	handler, _ := testRuntimeValidationServer0212(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	id, _ := createStagedIntegrityPackage0212(t, handler, token, "0385-stable-incomplete")
	req := httptest.NewRequest("GET", "/api/v1/packages/"+id+"/validations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validation: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			PublishReadiness publishReadiness0385 `json:"publishReadiness"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.PublishReadiness.Eligible {
		t.Fatal("missing v4 evidence must not be accepted")
	}
	found := false
	for _, b := range payload.Data.PublishReadiness.Blockers {
		if b.ReasonCode == "stable-runtime-target-blocked" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected concrete runtime target blocker: %+v", payload.Data.PublishReadiness.Blockers)
	}
}
