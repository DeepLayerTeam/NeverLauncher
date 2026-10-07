package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func testRuntimeValidationServer0212(t *testing.T) (http.Handler, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keys, err := json.Marshal(map[string]string{"ci-test": base64.RawURLEncoding.EncodeToString(publicKey)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		HTTPAddr:                  "127.0.0.1:0",
		PublicURL:                 "http://example.test",
		RepositoryDriver:          "memory",
		StorageDriver:             "local",
		StorageLocalPath:          t.TempDir(),
		BackupRoot:                t.TempDir(),
		CORSAllowedOrigins:        []string{"http://example.test"},
		Environment:               "test",
		AuthTokenSecret:           "test-secret-for-runtime-validation",
		AuthTokenTTLHours:         1,
		WebAuthnRPID:              "example.test",
		WebAuthnRPName:            "NeverLauncher Test",
		WebAuthnOrigins:           []string{"http://example.test"},
		MetricsEnabled:            true,
		RuntimeValidationKeysJSON: string(keys),
	}
	return Server{Version: "0.21.2-test", Config: cfg, Repo: repository.NewMemoryRepository(cfg.PublicURL), Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler(), privateKey
}

func createStagedIntegrityPackage0212(t *testing.T, handler http.Handler, token, version string) (string, string) {
	t.Helper()
	auth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages", strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"`+version+`"}`))
	req.Header.Set("Content-Type", "application/json")
	auth(req)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create package => %d %s", res.Code, res.Body.String())
	}
	var created struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.Data.PackageID == "" {
		t.Fatalf("package id missing: %v %s", err, res.Body.String())
	}
	packageID := created.Data.PackageID

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("path", "mods/honest-validation.jar")
	part, _ := writer.CreateFormFile("file", "honest-validation.jar")
	_, _ = part.Write([]byte("neverlauncher-0.21.2-runtime-validation"))
	_ = writer.Close()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	auth(req)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("upload => %d %s", res.Code, res.Body.String())
	}

	for _, suffix := range []string{"validate", "sign", "stage", "integrity-check"} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/"+suffix, nil)
		auth(req)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s => %d %s", suffix, res.Code, res.Body.String())
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/"+packageID+"/validations", nil)
	auth(req)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("validations => %d %s", res.Code, res.Body.String())
	}
	var validations struct {
		Data struct {
			Integrity struct {
				ManifestDigest string `json:"manifestDigest"`
				Result         string `json:"result"`
			} `json:"integrity"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &validations); err != nil {
		t.Fatal(err)
	}
	if validations.Data.Integrity.Result != "passed" || len(validations.Data.Integrity.ManifestDigest) != 64 {
		t.Fatalf("unexpected integrity result: %s", res.Body.String())
	}
	return packageID, validations.Data.Integrity.ManifestDigest
}

func TestLegacySmokeIsIntegrityOnly0212(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	packageID, _ := createStagedIntegrityPackage0212(t, handler, token, "0.21.2-smoke-honest")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/smoke-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("legacy smoke => %d %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	for _, required := range []string{`"validationKind":"integrity"`, `"runtimeExecuted":false`, `"runtimeStatus":"not-checked"`} {
		if !strings.Contains(body, required) {
			t.Fatalf("legacy smoke is not honest: missing %s in %s", required, body)
		}
	}
	if strings.Contains(body, `"runtimeStatus":"passed"`) || strings.Contains(body, `"validationKind":"runtime"`) {
		t.Fatalf("integrity-only smoke must never claim runtime pass: %s", body)
	}
}

func TestRuntimePolicyRequiresSignedExactManifestEvidence0212(t *testing.T) {
	handler, privateKey := testRuntimeValidationServer0212(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	packageID, manifestDigest := createStagedIntegrityPackage0212(t, handler, token, "0.21.2-runtime-policy")

	policyReq := httptest.NewRequest(http.MethodPut, "/api/v1/projects/demo-project/validation-policy", strings.NewReader(`{"requiredLevel":"runtime","requireServerJoin":true}`))
	policyReq.Header.Set("Authorization", "Bearer "+token)
	policyReq.Header.Set("Content-Type", "application/json")
	policyRes := httptest.NewRecorder()
	handler.ServeHTTP(policyRes, policyReq)
	if policyRes.Code != http.StatusOK {
		t.Fatalf("set runtime policy => %d %s", policyRes.Code, policyRes.Body.String())
	}

	publish := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/publish", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	if res := publish(); res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "runtime PASS") {
		t.Fatalf("publish without runtime evidence must fail => %d %s", res.Code, res.Body.String())
	}

	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	evidence := runtimeValidationEvidence0212{
		SchemaVersion:    runtimeValidationSchema0212,
		PackageID:        packageID,
		ManifestDigest:   manifestDigest,
		TargetID:         "linux-x86_64-java21",
		MinecraftVersion: "1.21.1",
		Loader:           "vanilla",
		OS:               "linux",
		Arch:             "amd64",
		Java:             "21",
		ActualClient:     true,
		ExitCode:         0,
		ServerJoin:       true,
		RunID:            "ci-run-0212",
		Commit:           strings.Repeat("a", 40),
		EvidenceHashes:   map[string]string{"client.log": strings.Repeat("b", 64)},
		StartedAt:        now,
		FinishedAt:       now.Add(30 * time.Second),
	}
	canonical, err := canonicalRuntimeEvidence0212(evidence)
	if err != nil {
		t.Fatal(err)
	}
	submission := runtimeValidationSubmission0212{KeyID: "ci-test", Evidence: evidence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
	payload, _ := json.Marshal(submission)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/runtime-validations/evidence", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), `"result":"passed"`) {
		t.Fatalf("signed runtime evidence => %d %s", res.Code, res.Body.String())
	}

	if res := publish(); res.Code != http.StatusOK {
		t.Fatalf("publish with signed exact runtime evidence => %d %s", res.Code, res.Body.String())
	}
}

func TestRuntimeEvidenceWithWrongSignatureIsRejected0212(t *testing.T) {
	handler, _ := testRuntimeValidationServer0212(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	packageID, manifestDigest := createStagedIntegrityPackage0212(t, handler, token, "0.21.2-bad-runtime-signature")
	now := time.Now().UTC().Add(-time.Minute)
	evidence := runtimeValidationEvidence0212{SchemaVersion: runtimeValidationSchema0212, PackageID: packageID, ManifestDigest: manifestDigest, TargetID: "linux", ActualClient: true, RunID: "bad-sig", EvidenceHashes: map[string]string{"log": strings.Repeat("c", 64)}, StartedAt: now, FinishedAt: now.Add(time.Second)}
	submission := runtimeValidationSubmission0212{KeyID: "ci-test", Evidence: evidence, Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	payload, _ := json.Marshal(submission)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/runtime-validations/evidence", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("invalid runtime signer must be rejected => %d %s", res.Code, res.Body.String())
	}
}
