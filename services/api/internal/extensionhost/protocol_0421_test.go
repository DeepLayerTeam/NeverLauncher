package extensionhost

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Real authenticated HTTP handler tests; the request uses precisely the
// 0.42.0 SDK hello envelope so older built clients remain wire-compatible.
func TestHostHelloSDKCompatibility0421(t *testing.T) {
	for _, tc := range []struct {
		name, manifestAPI, wireProtocol, wireAPI, code string
		wantStatus                                     int
	}{
		{"existing-sdk", "1.0", "1.0", "1.0", "", 200},
		{"legacy-sdk", "3.7", "1.0", "", "", 200},
		{"wrong-host-protocol", "1.0", "2.0", "1.0", "HOST_PROTOCOL_MISMATCH", 409},
		{"wrong-extension-api", "1.0", "1.0", "2.0", "HOST_EXTENSION_API_MISMATCH", 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := repository.NewMemoryRepository("http://example.invalid")
			host := New(Config{}, repo, storage.NewLocalStorage(t.TempDir()))
			st := &processState{
				key:   Key{ExtensionID: "org.compat", Scope: "global"},
				token: "compat-secret", instanceID: "process-one", state: "starting",
				manifest: model.ExtensionManifest{API: tc.manifestAPI},
				helloCh:  make(chan struct{}),
			}
			host.tokens[st.token] = st
			hello := map[string]any{
				"protocolVersion": tc.wireProtocol,
				"extensionId":     st.key.ExtensionID,
				"instanceId":      st.instanceID,
				"pid":             0,
			}
			if tc.wireAPI != "" {
				hello["extensionApiVersion"] = tc.wireAPI
			}
			raw, err := json.Marshal(hello)
			if err != nil {
				t.Fatal(err)
			}
			send := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/v1/hello", bytes.NewReader(raw))
				r.RemoteAddr = "127.0.0.1:45931"
				r.Header.Set("Authorization", "Bearer "+st.token)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				host.handleHello(w, r)
				return w
			}
			w := send()
			if w.Code != tc.wantStatus {
				t.Fatalf("hello HTTP %d, expected %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			var reply map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if tc.code != "" {
				if reply["code"] != tc.code {
					t.Fatalf("reason %v, expected %s", reply["code"], tc.code)
				}
				if !st.helloAt.IsZero() {
					t.Fatal("incompatible host activated the extension")
				}
				return
			}
			if reply["protocolVersion"] != "1.0" || reply["extensionApiVersion"] != "1.0" || reply["instanceId"] != st.instanceID {
				t.Fatalf("incompatible hello response: %#v", reply)
			}
			if st.helloAt.IsZero() || st.state != "running" {
				t.Fatal("valid legacy/current hello was not activated")
			}
			again := send()
			if again.Code != http.StatusConflict {
				t.Fatalf("replayed hello HTTP %d", again.Code)
			}
			var rejected map[string]any
			if err := json.Unmarshal(again.Body.Bytes(), &rejected); err != nil {
				t.Fatal(err)
			}
			if rejected["code"] != "HOST_HELLO_ALREADY_COMPLETED" {
				t.Fatalf("hello replay accepted: %#v", rejected)
			}
		})
	}
}
