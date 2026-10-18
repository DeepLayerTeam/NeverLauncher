package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

// Every production instance exposes the build-time commit for exact-source
// Admin/Backend staging verification. An absent build identifier cannot pass GA.
func TestStatusAndHealthExposeSourceCommit0220(t *testing.T) {
	const source = "0123456789abcdef0123456789abcdef01234567"
	api := Server{Version: "0.22.0", SourceCommit: source, Storage: storage.NewLocalStorage(t.TempDir())}
	for _, item := range []struct {
		path string
		fn   http.HandlerFunc
	}{
		{"/health", api.health}, {"/api/v1/status", api.status},
	} {
		res := httptest.NewRecorder()
		item.fn.ServeHTTP(res, httptest.NewRequest(http.MethodGet, item.path, nil))
		if res.Code != http.StatusOK {
			t.Fatalf("%s status=%d", item.path, res.Code)
		}
		var status statusResponse
		if err := json.Unmarshal(res.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Version != "0.22.0" || status.SourceCommit != source {
			t.Fatalf("%s returned wrong build identity: %+v", item.path, status)
		}
	}
}
