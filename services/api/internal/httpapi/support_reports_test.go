package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportReportValidation03510(t *testing.T) {
	valid := playerSupportReport03510{SchemaVersion: "1.1", LauncherVersion: "0.35.10", GeneratedAtUnix: 12345, OS: "linux", Arch: "x86_64", Stage: "failed", Events: []playerSupportEvent03510{{Code: "download", Count: 2}}}
	if err := validateSupport03510(valid); err != nil {
		t.Fatal(err)
	}
	cases := []playerSupportReport03510{}
	leak := valid
	leak.Events = []playerSupportEvent03510{{Code: "Authorization: Bearer ABCDEF", Count: 1}}
	cases = append(cases, leak)
	leak = valid
	leak.OS = "/home/player/name"
	cases = append(cases, leak)
	leak = valid
	leak.Stage = "https://my-private-server"
	cases = append(cases, leak)
	leak = valid
	leak.LauncherVersion = "0.35.10\naccess_token=XYZ"
	cases = append(cases, leak)
	leak = valid
	leak.Events = []playerSupportEvent03510{{Code: "download", Count: 81}}
	cases = append(cases, leak)
	for _, bad := range cases {
		if err := validateSupport03510(bad); err == nil {
			t.Errorf("unsafe report accepted: %+v", bad)
		}
	}
}
func TestSupportReportSubmitRequiresLoginAndConsent03510(t *testing.T) {
	handler := testServer(t)
	body := `{"consent":false,"report":{"schemaVersion":"1.1","launcherVersion":"0.35.10","generatedAtUnix":12345,"os":"linux","arch":"x86_64","stage":"failed","events":[]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/reports", strings.NewReader(body))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code == http.StatusOK || resp.Code == http.StatusCreated {
		t.Fatal("anonymous report accepted")
	}
	token := loginAdmin(t, handler)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/reports", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("no-consent accepted: %d", resp.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/reports", strings.NewReader(strings.Replace(body, "\"consent\":false", "\"consent\":true", 1)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("consented submission failed: %d %s", resp.Code, resp.Body.String())
	}
	var returned map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &returned); err != nil {
		t.Fatal(err)
	}
	if len(returned["id"].(string)) != 32 {
		t.Fatal("missing server-generated support ID")
	}

	id := returned["id"].(string)
	// No unauthenticated operator enumeration, even when a support ID is known.
	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/operations/support-reports", nil))
	if anonymous.Code == http.StatusOK {
		t.Fatal("anonymous operator inbox allowed")
	}
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/operations/support-reports", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK || !strings.Contains(listResp.Body.String(), id) {
		t.Fatalf("report not in operator inbox: %d %s", listResp.Code, listResp.Body.String())
	}

}

func TestSupportReportRejectsUnknownFields03510(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	body := `{"consent":true,"report":{"schemaVersion":"1.1","launcherVersion":"0.35.10","generatedAtUnix":12345,"os":"linux","arch":"x86_64","stage":"failed","events":[],"rawLog":"Authorization: Bearer SECRET"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/reports", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", response.Code)
	}
}

func TestOperatorDiagnosticsDoesNotLeakInfrastructure03510(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations/diagnostics-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("operator export unavailable: %d", response.Code)
	}
	for _, s := range []string{"storageLocalPath", "storageS3Endpoint", "backupRoot", "storageS3Bucket", "databaseDsn", "authTokenSecret", "publicUrl", "corsAllowedOrigins"} {
		if strings.Contains(response.Body.String(), s) {
			t.Errorf("sensitive configuration key leaked: %s", s)
		}
	}
}
