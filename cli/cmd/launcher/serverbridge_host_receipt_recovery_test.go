package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A dropped HTTPS response after a side effect is never safe to replay.
// The CLI recovers the exact durable receipt through read-only host.status.
func TestRemoteReceiptRecovery0515(t *testing.T) {
	const key = "recover-original-key-0515"
	var mutations atomic.Int32
	var receiptReads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/host/commands":
			mutations.Add(1)
			// The operation committed on the host, but HTTP acknowledgement
			// was lost. A retry would repeat a potentially dangerous action.
			h, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server must allow connection drop")
				return
			}
			conn, _, err := h.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		case r.Method == http.MethodGet && r.URL.Path == "/v1/host/receipts/"+key:
			receiptReads.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schemaVersion":"1.0","state":"succeeded","action":"restart"}`))
		default:
			t.Errorf("unexpected remote request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 400)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	token := filepath.Join(dir, "token")
	output := filepath.Join(dir, "receipt.json")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("synthetic-credential\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"call", "--url", server.URL, "--ca-file", ca, "--token-file", token, "--idempotency-key", key, "--output", output}
	if err := remoteCall0284(append(append([]string{}, args...), "--action", "restart")); err == nil {
		t.Fatal("lost response must be reported as uncertain")
	}
	if err := remoteCall0284(append(append([]string{}, args...), "--action", "receipt")); err != nil {
		t.Fatalf("read-only original receipt recovery: %v", err)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"state": "succeeded"`) && !strings.Contains(string(content), `"state":"succeeded"`) {
		t.Fatalf("unexpected recovered receipt %s", content)
	}
	if mutations.Load() != 1 || receiptReads.Load() != 1 {
		t.Fatalf("recovery must not invoke command again: mutations=%d receipts=%d", mutations.Load(), receiptReads.Load())
	}
	// TLS validation is exercised with an actual trusted server certificate.
	// A missing CA must fail closed without a network call.
	if err := remoteCall0284([]string{"call", "--url", server.URL, "--token-file", token, "--action", "receipt", "--idempotency-key", key}); err == nil {
		t.Fatal("receipt recovery must not disable CA verification")
	}
}
