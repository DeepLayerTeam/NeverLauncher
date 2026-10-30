package hostcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func privateFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestRemoteLifecycle0413(t *testing.T) {
	var count atomic.Int32
	session := "initial"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 40) {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/host/status" {
			json.NewEncoder(w).Encode(map[string]any{"nodeId": "nodeA", "status": map[string]any{"configured": true, "processAlive": true, "supervisorAlive": true, "observedStatus": "running", "sessionId": session}})
			return
		}
		if r.URL.Path == "/v1/host/commands" && r.Header.Get("Idempotency-Key") == "operation-12345678901" {
			count.Add(1)
			session = "new"
			sum := sha256.Sum256([]byte(r.Header.Get("Idempotency-Key")))
			json.NewEncoder(w).Encode(map[string]any{"keyHash": hex.EncodeToString(sum[:]), "action": "restart", "state": "succeeded"})
			return
		}
		http.Error(w, "unknown", 404)
	}))
	defer server.Close()
	cert := server.TLS.Certificates[0].Certificate[0]
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	ca := privateFixture(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw})))
	tkn := privateFixture(t, strings.Repeat("x", 40))
	target := Target{URL: server.URL, NodeID: "nodeA", CAFile: ca, TokenFile: tkn}
	client, err := NewClient(target)
	if err != nil {
		t.Fatal(err)
	}
	before, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Execute(context.Background(), "restart", "operation-12345678901")
	if err != nil {
		t.Fatal(err)
	}
	after, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !Verified("restart", before, after, receipt) || count.Load() != 1 {
		t.Fatalf("not verified: %+v %+v", receipt, after)
	}
	if Verified("restart", after, after, receipt) {
		t.Fatal("same-session restart accepted")
	}
	if _, err := NewClient(Target{CAFile: ca, TokenFile: "missing"}); err == nil {
		t.Fatal("missing token accepted")
	}
	wrong := *client
	wrong.nodeID = "another-node"
	if _, err := wrong.Status(context.Background()); err == nil {
		t.Fatal("node ID mismatch accepted")
	}
}
