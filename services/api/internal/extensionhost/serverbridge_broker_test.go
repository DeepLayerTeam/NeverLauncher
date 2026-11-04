package extensionhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Production code is exercised through the authenticated HTTP broker. The
// ServerBridge store adapter below deterministically simulates V3 queue ACKs;
// PostgreSQL locking/idempotency are separately tested by the repository suite.
type javaBridgeStoreTest0488 struct {
	repository.Repository
	mu       sync.Mutex
	node     model.ServerBridgeNode
	commands map[string]model.ServerBridgeControlCommand
}

func (r *javaBridgeStoreTest0488) GetServerBridgeNode(_ context.Context, id string) (model.ServerBridgeNode, error) {
	if id != r.node.ID {
		return model.ServerBridgeNode{}, repository.ErrNotFound
	}
	return r.node, nil
}
func (r *javaBridgeStoreTest0488) ListServerBridgeNodes(context.Context) ([]model.ServerBridgeNode, error) {
	return []model.ServerBridgeNode{r.node}, nil
}
func (r *javaBridgeStoreTest0488) GetActiveServerBridgeJoinTicket(context.Context, string, string, time.Time) (model.ServerBridgeJoinTicket, error) {
	return model.ServerBridgeJoinTicket{}, repository.ErrNotFound
}
func (r *javaBridgeStoreTest0488) CreateServerBridgeControlCommand(_ context.Context, c model.ServerBridgeControlCommand, _ time.Time) (model.ServerBridgeControlCommand, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := c.ServerID + ":" + c.RequestedBy + ":" + c.IdempotencyKey
	if original, ok := r.commands[key]; ok {
		if original.RequestDigest != c.RequestDigest {
			return model.ServerBridgeControlCommand{}, false, repository.ErrConflict
		}
		return original, true, nil
	}
	r.commands[key] = c
	return c, false, nil
}
func (r *javaBridgeStoreTest0488) GetServerBridgeControlCommand(_ context.Context, serverID, commandID string) (model.ServerBridgeControlCommand, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.commands {
		if c.ID == commandID && c.ServerID == serverID {
			return c, nil
		}
	}
	return model.ServerBridgeControlCommand{}, repository.ErrNotFound
}
func TestJavaBridgeAuthenticatedBroker0488(t *testing.T) {
	ctx := context.Background()
	base := repository.NewMemoryRepository("http://example.test")
	_, err := base.SaveProject(model.Project{ID: "p1", Name: "Project"})
	if err != nil {
		t.Fatal(err)
	}
	ext := "org.bridge0488"
	permissions := []string{"serverbridge:read", "gameserver:broadcast", "project:read"}
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: ext, Name: "Bridge", Version: "1.0.0", Publisher: "test", API: "1.0",
		Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/java-host.jar"}}, Permissions: permissions}
	if _, err := base.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	for _, p := range permissions {
		if _, err := base.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: ext, Scope: "project", ScopeID: "p1", Permission: p, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	repo := &javaBridgeStoreTest0488{Repository: base, commands: map[string]model.ServerBridgeControlCommand{}, node: model.ServerBridgeNode{
		ID: "server1", ProjectID: "p1", Name: "A server", Kind: "paper", ServerBrand: "Paper", Status: "active", ProtocolVersion: 3,
		RuntimeEpoch: 2, RuntimeID: strings.Repeat("a", 64), RuntimeLastSeenAt: now, IntegrityStatus: "verified", RuntimeCapabilities: []string{"adapter.control.broadcast"}}}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Close(done)
	})
	st := &processState{key: Key{ExtensionID: ext, Scope: "project", ScopeID: "p1"}, install: model.ExtensionInstall{ExtensionID: ext, Scope: "project", ScopeID: "p1", CurrentVersion: "1.0.0"},
		manifest: manifest, token: "bridge-0488-token", instanceID: "bridge-0488-run", state: "running"}
	host.mu.Lock()
	host.tokens[st.token] = st
	host.mu.Unlock()
	call := func(operation string, body map[string]any) (int, map[string]any) {
		t.Helper()
		blob, _ := json.Marshal(body)
		req, e := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/"+operation, bytes.NewReader(blob))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+st.token)
		req.Header.Set("Content-Type", "application/json")
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if res.StatusCode == 200 {
			if e = json.Unmarshal(raw, &response); e != nil {
				t.Fatalf("invalid JSON: %s", raw)
			}
		}
		return res.StatusCode, response
	}
	if status, _ := call("bridge.server", map[string]any{"projectId": "p2", "serverId": "server1"}); status != 403 {
		t.Fatalf("cross project %d", status)
	}
	status, result := call("bridge.server", map[string]any{"projectId": "p1", "serverId": "server1"})
	if status != 200 {
		t.Fatalf("live status=%d", status)
	}
	server := result["server"].(map[string]any)
	if server["projectId"] != "p1" || server["runtimeActive"] != true {
		t.Fatalf("bad live status: %v", server)
	}
	for _, secret := range []string{"tokenHash", "keyFingerprint", "publicKey", "pluginSha256"} {
		if _, ok := server[secret]; ok {
			t.Fatalf("secret leaked %s", secret)
		}
	}
	status, _ = call("bridge.servers", map[string]any{"projectId": "p1", "offset": 0, "limit": 1})
	if status != 200 {
		t.Fatalf("server list=%d", status)
	}
	status, _ = call("bridge.access.ticket", map[string]any{"projectId": "p1", "serverId": "server1", "username": "Player1"})
	if status != 200 {
		t.Fatalf("ticket check=%d", status)
	}
	request := map[string]any{"projectId": "p1", "serverId": "server1", "commandType": "message.broadcast", "payload": map[string]string{"message": "Test broadcast"}, "idempotencyKey": "java-0488-repeat", "expiresInSeconds": 120}
	status, out := call("bridge.command.create", request)
	if status != 200 {
		t.Fatalf("command create=%d", status)
	}
	command := out["command"].(map[string]any)
	if command["status"] != "pending" {
		t.Fatalf("command not queued: %v", command)
	}
	status, replay := call("bridge.command.create", request)
	if status != 200 || replay["idempotentReplay"] != true {
		t.Fatalf("idempotent replay failed: %d %v", status, replay)
	}
	request["payload"] = map[string]string{"message": "Different"}
	if status, _ = call("bridge.command.create", request); status != 409 {
		t.Fatalf("idempotency conflict not rejected: %d", status)
	}
	request["commandType"] = "server.console"
	request["payload"] = map[string]string{"command": "op"}
	if status, _ = call("bridge.command.create", request); status == 200 {
		t.Fatal("console bypass admitted")
	}
	status, _ = call("bridge.command.get", map[string]any{"projectId": "p1", "serverId": "server1", "commandId": command["id"]})
	if status != 200 {
		t.Fatalf("command read %d", status)
	}
	if err := base.RevokeExtensionPermission(ctx, ext, "project", "p1", "gameserver:broadcast"); err != nil {
		t.Fatal(err)
	}
	request["commandType"] = "message.broadcast"
	request["payload"] = map[string]string{"message": "Not allowed"}
	if status, _ = call("bridge.command.create", request); status != 403 {
		t.Fatalf("revoked command still allowed %d", status)
	}
	if status, _ = call("bridge.command.get", map[string]any{"projectId": "p1", "serverId": "server1", "commandId": command["id"]}); status != 403 {
		t.Fatalf("revoked command read %d", status)
	}
	if err := base.RevokeExtensionPermission(ctx, ext, "project", "p1", "serverbridge:read"); err != nil {
		t.Fatal(err)
	}
	if status, _ = call("bridge.server", map[string]any{"projectId": "p1", "serverId": "server1"}); status != 403 {
		t.Fatalf("revoked read still allowed %d", status)
	}
}
