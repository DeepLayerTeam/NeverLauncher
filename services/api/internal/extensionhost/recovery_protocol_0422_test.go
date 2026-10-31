package extensionhost

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// If Stop races Java's hello, the old bearer token must not turn a stopped
// instance back into RUNNING or register a callback endpoint.
func TestJavaLateHelloCannotUndoOperatorStop0422(t *testing.T) {
	host := New(Config{}, repository.NewMemoryRepository("http://localhost"), nil)
	st := &processState{
		key:   Key{ExtensionID: "org.example.stop-race", Scope: "global"},
		token: "old-process-token", instanceID: "stopped-instance", state: "stopping",
		expectedStop: true, javaHost: true, helloCh: make(chan struct{}),
		manifest: model.ExtensionManifest{API: "1.0"},
	}
	host.tokens[st.token] = st
	body, err := json.Marshal(map[string]any{
		"protocolVersion": "1.0", "extensionApiVersion": "1.0",
		"extensionId": st.key.ExtensionID, "instanceId": st.instanceID,
		"pid": 0, "callbackUrl": "http://127.0.0.1:46701",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/hello", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:47111"
	r.Header.Set("Authorization", "Bearer "+st.token)
	w := httptest.NewRecorder()
	host.handleHello(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("late hello accepted: HTTP %d: %s", w.Code, w.Body.String())
	}
	var answer map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer["code"] != "HOST_INSTANCE_NOT_STARTING" || st.state != "stopping" || !st.helloAt.IsZero() || st.callbackURL != "" {
		t.Fatalf("stopped instance activated or negotiated callback: %+v %+v", answer, st)
	}
}
