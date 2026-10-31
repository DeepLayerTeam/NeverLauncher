package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func remoteFixture0284(t *testing.T) (*remoteAgent0284, remoteIdentity0284, string) {
	t.Helper()
	root := t.TempDir()
	id, err := remoteInit0284(root)
	if err != nil {
		t.Fatal(err)
	}
	a, err := remoteNewAgent0284(root, id, []string{"127.0.0.0/8", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	return a, id, root
}
func remoteTokenFixture0284(t *testing.T, id remoteIdentity0284, scopes ...string) string {
	t.Helper()
	token, err := remoteIssue0284(id, "service-ci", scopes, []string{"127.0.0.0/8"}, 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func remoteRequest0284(t *testing.T, a *remoteAgent0284, token, method, path, action, key, remoteIP string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if action != "" {
		body = strings.NewReader(fmt.Sprintf(`{"action":%q}`, action))
	}
	req := httptest.NewRequest(method, "https://remote.example"+path, body)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	req.RemoteAddr = remoteIP
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}
func TestRemoteControlScopesAndSources0284(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.status")
	status := remoteRequest0284(t, a, token, "GET", "/v1/host/status", "", "", "127.0.0.1:4000")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), id.NodeID) {
		t.Fatalf("status=%d %s", status.Code, status.Body.String())
	}
	for name, request := range map[string]func() *httptest.ResponseRecorder{
		"cannot start with status": func() *httptest.ResponseRecorder {
			return remoteRequest0284(t, a, token, "POST", "/v1/host/commands", "start", "start-request-123456", "127.0.0.1:4000")
		},
		"no shell": func() *httptest.ResponseRecorder {
			return remoteRequest0284(t, a, token, "POST", "/v1/host/commands", "shell", "start-request-123456", "127.0.0.1:4000")
		},
		"no backend": func() *httptest.ResponseRecorder {
			return remoteRequest0284(t, a, token, "POST", "/v1/host/commands", "backend.restart", "start-request-123456", "127.0.0.1:4000")
		},
		"unapproved source": func() *httptest.ResponseRecorder {
			return remoteRequest0284(t, a, token, "GET", "/v1/host/status", "", "", "192.0.2.5:4000")
		},
		"no TLS": func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("GET", "http://remote.example/v1/host/status", nil)
			req.RemoteAddr = "127.0.0.1:4000"
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			return w
		},
		"bad URL": func() *httptest.ResponseRecorder {
			return remoteRequest0284(t, a, token, "GET", "/v1/nonexistent", "", "", "127.0.0.1:4000")
		},
	} {
		t.Run(name, func(t *testing.T) {
			rr := request()
			if rr.Code < 400 {
				t.Fatalf("status %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}
func TestRemoteControlIdempotencyAndUnknown0284(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start", "host.stop")
	var count atomic.Int32
	a.execute = func(action string) (json.RawMessage, error) { count.Add(1); return json.RawMessage(`{"ok":true}`), nil }
	call := func(action, key string) *httptest.ResponseRecorder {
		return remoteRequest0284(t, a, token, "POST", "/v1/host/commands", action, key, "127.0.0.1:23000")
	}
	key := "idempotency-id-000000001"
	first := call("start", key)
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"succeeded"`) {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
	second := call("start", key)
	if second.Code != 200 || count.Load() != 1 {
		t.Fatalf("replayed=%d count=%d", second.Code, count.Load())
	}
	if changed := call("stop", key); changed.Code != 409 || count.Load() != 1 {
		t.Fatalf("changed %d", changed.Code)
	}
	if missing := call("start", ""); missing.Code != 400 {
		t.Fatalf("missing idem %d", missing.Code)
	}
	// Restarted agent loads receipts from disk. No second execution is allowed.
	b, err := remoteNewAgent0284(root, id, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	b.execute = func(string) (json.RawMessage, error) { count.Add(1); return nil, nil }
	replay := remoteRequest0284(t, b, token, "POST", "/v1/host/commands", "start", key, "127.0.0.1:23000")
	if replay.Code != 200 || count.Load() != 1 {
		t.Fatalf("restart replay %d %d", replay.Code, count.Load())
	}
	// Crash while the external effect was running: indeterminate, NEVER retry.
	uncertainKey := "indeterminate-id-00001"
	path := remoteReceiptFile0284(remoteDir0284(root), uncertainKey)
	h := remoteReceipt0284{SchemaVersion: "1.0", KeyHash: strings.TrimSuffix(filepath.Base(path), ".json"), Digest: remoteDigestFixture0284("start", "service-ci", id.NodeID), Subject: "service-ci", Action: "start", State: "indeterminate", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err = remotePersistReceipt0284(path, h); err != nil {
		t.Fatal(err)
	}
	replay = remoteRequest0284(t, b, token, "POST", "/v1/host/commands", "start", uncertainKey, "127.0.0.1:23000")
	if replay.Code != 409 || count.Load() != 1 || !strings.Contains(replay.Body.String(), "indeterminate") {
		t.Fatalf("unknown %d %s", replay.Code, replay.Body.String())
	}
	audit, err := os.ReadFile(filepath.Join(remoteDir0284(root), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(audit, []byte("accepted")) || strings.Contains(string(audit), token) {
		t.Fatalf("audit missing/credential leak: %s", audit)
	}
}
func remoteDigestFixture0284(action, subject, node string) string {
	sum := sha256.Sum256([]byte(action + "\x00" + subject + "\x00" + node))
	return hex.EncodeToString(sum[:])
}
func TestRemoteTokenSecurity0284(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.status")
	wrong, _ := remoteInit0284(t.TempDir())
	if _, err := remoteTokenDecode0284(wrong, token, time.Now()); err == nil {
		t.Fatal("cross-node token accepted")
	}
	if _, err := remoteTokenDecode0284(id, token+"x", time.Now()); err == nil {
		t.Fatal("modified signature accepted")
	}
	if _, err := remoteIssue0284(id, "service", []string{"host.exec"}, []string{"127.0.0.1/32"}, time.Minute, time.Now()); err == nil {
		t.Fatal("host exec scope should not exist")
	}
	if _, err := remoteIssue0284(id, "service", []string{"host.status"}, []string{"127.0.0.1/32"}, time.Hour, time.Now()); err == nil {
		t.Fatal("long-lived token issued")
	}
	if _, err := remoteIssue0284(id, "service", []string{"host.status"}, []string{"invalid"}, time.Minute, time.Now()); err == nil {
		t.Fatal("bad CIDR accepted")
	}
	if _, err := remoteTokenDecode0284(id, token, time.Now().Add(16*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	c, err := remoteTokenDecode0284(id, token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = remoteRevokeToken0284(remoteDir0284(root), c, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp := remoteRequest0284(t, a, token, "GET", "/v1/host/status", "", "", "127.0.0.1:4000")
	if resp.Code != 401 {
		t.Fatalf("revoked accepted: %d", resp.Code)
	}
}
func TestRemoteControlConcurrentDelivery0284(t *testing.T) {
	a, id, _ := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.start")
	var executed atomic.Int32
	a.execute = func(string) (json.RawMessage, error) {
		executed.Add(1)
		time.Sleep(25 * time.Millisecond)
		return json.RawMessage(`{"ok":true}`), nil
	}
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- remoteRequest0284(t, a, token, "POST", "/v1/host/commands", "start", "same-command-0000001", "127.0.0.1:7000").Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("concurrent request returned %d", code)
		}
	}
	if executed.Load() != 1 {
		t.Fatalf("executed %d times", executed.Load())
	}
}

func TestRemoteControlRealHTTPSAndCLI0284(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.status", "host.start")
	server := httptest.NewTLSServer(a)
	defer server.Close()
	ca := filepath.Join(root, "ca.pem")
	cert := server.Certificate()
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\n"+base64.StdEncoding.EncodeToString(cert.Raw)+"\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(root, "service.token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "reply.json")
	if err := handleServerBridgeHost01910([]string{"remote", "call", "--url", server.URL, "--token-file", tokenFile, "--ca-file", ca, "--action", "status", "--output", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(id.NodeID)) {
		t.Fatalf("status response=%s", data)
	}
	if err = remoteCall0284([]string{"--url", server.URL, "--token-file", tokenFile, "--ca-file", ca, "--action", "start"}); err == nil {
		t.Fatal("mutation missing idempotency key accepted")
	}
	if err = remoteCall0284([]string{"--url", server.URL + "?token=secret", "--token-file", tokenFile, "--ca-file", ca}); err == nil {
		t.Fatal("query secrets must not be allowed")
	}
	if err = remoteCall0284([]string{"--url", server.URL, "--token-file", tokenFile, "--ca-file", tokenFile}); err == nil {
		t.Fatal("insecure CA was accepted")
	}
}

func TestRemoteKeyRotationLiveAndLease0284(t *testing.T) {
	a, id, root := remoteFixture0284(t)
	token := remoteTokenFixture0284(t, id, "host.status")
	release, err := remoteAcquireLease0284(remoteDir0284(root), id.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remoteAcquireLease0284(remoteDir0284(root), id.NodeID); err == nil {
		t.Fatal("second agent accepted on same server root")
	}
	release()
	release, err = remoteAcquireLease0284(remoteDir0284(root), id.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	release()
	key, err := remoteRandom0284(32)
	if err != nil {
		t.Fatal(err)
	}
	id.Key = key
	if err = remoteSave0284(filepath.Join(remoteDir0284(root), "identity.json"), id); err != nil {
		t.Fatal(err)
	}
	old := remoteRequest0284(t, a, token, "GET", "/v1/host/status", "", "", "127.0.0.1:4000")
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("token survived key rotation: %d", old.Code)
	}
	newToken := remoteTokenFixture0284(t, id, "host.status")
	next := remoteRequest0284(t, a, newToken, "GET", "/v1/host/status", "", "", "127.0.0.1:4000")
	if next.Code != http.StatusOK {
		t.Fatalf("new token rejected after rotation: %d", next.Code)
	}
}

func TestRemoteControlRealSupervisorStop0284(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake JVM fixture")
	}
	a, id, root := remoteFixture0284(t)
	jar := filepath.Join(root, "paper.jar")
	if err := os.WriteFile(jar, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, `echo ready; while IFS= read -r cmd; do if [ "$cmd" = "stop" ]; then echo graceful-exit; exit 0; fi; done`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", jar, "--java", java, "--restart-policy", "never", "--stop-timeout-seconds", "3"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runServerBridgeHost01910(root, false) }()
	paths := hostPaths01910(root)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		log, _ := os.ReadFile(paths["stdout"])
		state, err := readServerBridgeHostRuntime01910(paths["runtime"])
		if err == nil && state.Status == "running" && bytes.Contains(log, []byte("ready")) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	token := remoteTokenFixture0284(t, id, "host.stop")
	response := remoteRequest0284(t, a, token, "POST", "/v1/host/commands", "stop", "supervisor-stop-000000001", "127.0.0.1:4444")
	if response.Code != 200 {
		t.Fatalf("stop command: %d %s", response.Code, response.Body.String())
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervisor: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote stop didn't terminate JVM")
	}
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "stopped" || state.ProcessPID != 0 {
		t.Fatalf("unexpected runtime state: %+v", state)
	}
}

func TestHostObservedPostconditions0413(t *testing.T) {
	before := map[string]any{"sessionId": "session-previous", "processAlive": true, "supervisorAlive": true, "observedStatus": "running"}
	stopped := map[string]any{"sessionId": "session-previous", "processAlive": false, "supervisorAlive": false, "observedStatus": "stopped"}
	if !remoteObservedEffect0413("stop", before, stopped) {
		t.Fatal("verified stop not recognized")
	}
	if remoteObservedEffect0413("restart", before, before) {
		t.Fatal("unchanged session verified as restart")
	}
	if remoteObservedEffect0413("start", stopped, map[string]any{"processAlive": false, "supervisorAlive": true, "observedStatus": "starting"}) {
		t.Fatal("planned JVM start verified without process")
	}
	running := map[string]any{"sessionId": "session-new", "processAlive": true, "supervisorAlive": true, "observedStatus": "running"}
	if !remoteObservedEffect0413("restart", before, running) || !remoteObservedEffect0413("start", stopped, running) {
		t.Fatal("verified JVM execution denied")
	}
	if remoteObservedEffect0413("stop", before, map[string]any{"sessionId": "session-previous", "processAlive": false, "supervisorAlive": true, "observedStatus": "stopped"}) {
		t.Fatal("live supervisor ignored during shutdown")
	}
}
