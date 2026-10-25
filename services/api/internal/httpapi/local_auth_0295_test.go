package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/fileauth"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

func TestImportedFileAuthLocalLoginAndAtomicRehash0295(t *testing.T) {
	r := repository.NewMemoryRepository("http://localhost")
	sum := sha256.Sum256([]byte("imported password"))
	legacy, err := fileauth.EncodeCredential("sha256-hex", hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	const id = "gravit-fileauth-8af62031233343338333000000000001"
	user, err := r.SaveUser(model.User{ID: id, Email: "migrated_01@fileauth.invalid", DisplayName: "Migrated_01", Status: "active", RoleID: "player", PasswordHash: legacy})
	if err != nil {
		t.Fatal(err)
	}
	uuid := "8af62031-2333-4333-8333-000000000001"
	_, err = r.SaveMinecraftProfile(model.MinecraftProfile{UserID: id, UUID: uuid, Name: "Migrated_01", Issuer: "neverlauncher", Realm: "local", Subject: uuid})
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewFederationCore112(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "local", authconnector.PasswordRequest{Identifier: "Migrated_01", Secret: "wrong"}); err == nil {
		t.Fatal("wrong password accepted")
	}
	before, err := r.GetUser(id)
	if err != nil || before.PasswordHash != legacy {
		t.Fatal("failed login mutated password")
	}
	result, err := core.AuthenticatePassword(context.Background(), "local", authconnector.PasswordRequest{Identifier: "Migrated_01", Secret: "imported password"})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.ID != id || result.Identity.Issuer != "neverlauncher" {
		t.Fatalf("wrong canonical identity %+v", result.Identity)
	}
	after, err := r.GetUser(id)
	if err != nil || !strings.HasPrefix(after.PasswordHash, "$argon2id$") || after.PasswordHash == legacy || !localpassword.Verify("imported password", after.PasswordHash) {
		t.Fatal("Argon2id upgrade missing or invalid")
	}
	profile, err := r.GetMinecraftProfileByUser(id)
	if err != nil || profile.UUID != uuid {
		t.Fatalf("UUID changed after rehash %+v %v", profile, err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "local", authconnector.PasswordRequest{Identifier: "Migrated_01", Secret: "imported password"}); err != nil {
		t.Fatal("post-rehash login", err)
	}
	again, err := r.GetUser(id)
	if err != nil || again.PasswordHash != after.PasswordHash {
		t.Fatal("hash must not change again without password rotation")
	}
	disabled, err := r.SetUserDisabled(user.ID, true)
	if err != nil || disabled.Status != "disabled" {
		t.Fatal("disable failed", err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "local", authconnector.PasswordRequest{Identifier: "Migrated_01", Secret: "imported password"}); err == nil {
		t.Fatal("disabled imported account logged in")
	}
}

// Exercises the actual Yggdrasil route, not only a standalone hash verifier.
// An imported player must keep their original Gravit Minecraft UUID when
// authenticating through an unchanged Minecraft authlib client.
func TestImportedFileAuthYggdrasilLoginPreservesUUID0295(t *testing.T) {
	r := repository.NewMemoryRepository("http://localhost")
	const uuid = "8af62031-2333-4333-8333-000000000041"
	const id = "gravit-fileauth-8af62031233343338333000000000041"
	sum := sha256.Sum256([]byte("Known-gravit-password"))
	legacy, err := fileauth.EncodeCredential("sha256-hex", hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.SaveUser(model.User{ID: id, Email: "legacy_41@fileauth.invalid", DisplayName: "Legacy_41", RoleID: "player", Status: "active", PasswordHash: legacy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.SaveMinecraftProfile(model.MinecraftProfile{UserID: id, UUID: uuid, Name: "Legacy_41", Issuer: "neverlauncher", Realm: "local", Subject: uuid})
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewFederationCore112(r)
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Version: "0.29.5", Config: config.Config{Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "012345678901234567890123456789012345"}, Repo: r, State: NewRuntimeState(), Federation: core}
	h := s.Handler()
	makeRequest := func(password string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"username": "Legacy_41", "password": password, "providerId": "local", "clientToken": "fileauth-legacy-client"})
		req := httptest.NewRequest(http.MethodPost, "/authserver/authenticate", bytes.NewReader(body))
		result := httptest.NewRecorder()
		h.ServeHTTP(result, req)
		return result
	}
	if result := makeRequest("wrong-password"); result.Code != http.StatusForbidden {
		t.Fatalf("wrong password status: %d", result.Code)
	}
	result := makeRequest("Known-gravit-password")
	if result.Code != http.StatusOK {
		t.Fatalf("real Yggdrasil login failed %d: %s", result.Code, result.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(result.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	selected, ok := payload["selectedProfile"].(map[string]any)
	if !ok || selected["id"] != strings.ReplaceAll(uuid, "-", "") || selected["name"] != "Legacy_41" {
		t.Fatalf("migrated Minecraft UUID/name mismatch: %#v", payload)
	}
	after, err := r.GetUser(id)
	if err != nil || !strings.HasPrefix(after.PasswordHash, "$argon2id$") {
		t.Fatalf("Yggdrasil login failed to upgrade known legacy password: %v", err)
	}
}
