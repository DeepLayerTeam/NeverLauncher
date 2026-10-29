package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const sqliteTestSecret0373 = "test-secret-must-be-stable-for-0373-and-very-long"

func openSQLiteRuntimeTest0373(t *testing.T, path, secret string) (*repository.SQLiteHTTPRepository0372, *RuntimeState) {
	t.Helper()
	repo, err := repository.OpenSQLiteHTTPRepository0372(context.Background(), path, "https://launcher.test")
	if err != nil {
		t.Fatal(err)
	}
	state := NewRuntimeState()
	if err := ConfigureSQLiteRuntime0373(context.Background(), state, repo, secret); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	return repo, state
}
func TestSQLiteRuntimeRestartAndSingleUse0373(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launcher.db")
	repo, state := openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	user := model.User{ID: "u-1", Email: "user@example.test", RoleID: "owner", Status: "active"}
	req := httptest.NewRequest("POST", "https://launcher.test/api/v1/auth/login", nil)
	session, refresh, err := state.AuthSessions.create(user, req, "pc")
	if err != nil {
		t.Fatal(err)
	}
	code := "REFRESH-ONE-TIME-0373"
	state.Security.mu.Lock()
	state.Security.mfa[user.ID] = mfaRecord{Enabled: true, ActiveSecret: "DO-NOT-PERSIST-PLAINTEXT", Recovery: map[string]string{hashSecurityToken902(code): "active"}}
	state.Security.mu.Unlock()
	token, rec, err := state.Security.createOneTimeToken(user.ID, user.Email, "password-reset", time.Hour)
	if err != nil || rec.TokenHash == "" {
		t.Fatalf("token create: %v", err)
	}
	challengeToken, err := state.Passkeys.createChallenge(user.ID, "register", []byte("test-challenge"), map[string]any{"challenge": "testing"})
	if err != nil {
		t.Fatal(err)
	}
	cred := passkeyCredential117{ID: "passkey-1", UserID: user.ID, CredentialID: []byte("credential-unique"), UserHandle: []byte("handle"), PublicKeyCOSE: []byte("cose"), AAGUID: []byte("aaguid"), Status: "active"}
	if err := state.Passkeys.saveCredential(cred); err != nil {
		t.Fatal(err)
	}
	state.ServerBridge.mu.Lock()
	state.ServerBridge.servers["node-1"] = bridgeServerRecord{ID: "node-1", Status: "active", TokenHash: "bridge-token-hash", TokenPrefix: "br", PublicKey: "public-key"}
	state.ServerBridge.nodeNonces["nonce-hash"] = time.Now().UTC()
	state.ServerBridge.mu.Unlock()
	cipher, found, err := repo.ReadRuntimeComponent0373(context.Background(), "security")
	if err != nil || !found || bytes.Contains(cipher, []byte("DO-NOT-PERSIST-PLAINTEXT")) {
		t.Fatalf("security ciphertext missing or leaked secret: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, state = openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	defer repo.Close()
	if _, ok := state.AuthSessions.get(session.ID, user.ID); !ok {
		t.Fatal("lost session")
	}
	if !state.Security.totpEnabled(user.ID) {
		t.Fatal("MFA not restored")
	}
	if !state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("lost recovery code")
	}
	if state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("reused recovery code")
	}
	if _, ok := state.Security.consumeOneTimeToken(token, "password-reset"); !ok {
		t.Fatal("lost password reset token")
	}
	if _, err := state.Passkeys.consumeChallenge(challengeToken, "register"); err != nil {
		t.Fatalf("lost challenge: %v", err)
	}
	if _, err := state.Passkeys.credentialByRawID(cred.CredentialID); err != nil {
		t.Fatal(err)
	}
	if state.ServerBridge.servers["node-1"].TokenHash != "bridge-token-hash" {
		t.Fatal("lost bridge identity hash")
	}
	if _, ok := state.ServerBridge.nodeNonces["nonce-hash"]; !ok {
		t.Fatal("lost bridge replay nonce")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, state = openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	defer repo.Close()
	if state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("recovery code replay after restart")
	}
	if _, ok := state.Security.consumeOneTimeToken(token, "password-reset"); ok {
		t.Fatal("password reset replay after restart")
	}
	if _, err := state.Passkeys.consumeChallenge(challengeToken, "register"); err == nil {
		t.Fatal("WebAuthn challenge replay after restart")
	}
	if _, next, err := state.AuthSessions.rotate(refresh); err != nil || next == "" {
		t.Fatalf("refresh lost after restart: %v", err)
	}
	if _, _, err := state.AuthSessions.rotate(refresh); !errors.Is(err, errRefreshTokenReuseDetected) {
		t.Fatalf("refresh reuse not detected: %v", err)
	}
}
func TestSQLiteRuntimeRejectsWrongKey0373(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launcher.db")
	repo, state := openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	state.Security.setEmailVerified("user", true)
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := repository.OpenSQLiteHTTPRepository0372(context.Background(), path, "https://launcher.test")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := ConfigureSQLiteRuntime0373(context.Background(), NewRuntimeState(), repo, "another-secret-with-more-than-32-characters"); err == nil {
		t.Fatal("wrong decryption key must fail closed")
	}
}
func TestSQLiteRuntimeCommitFailurePoison0373(t *testing.T) {
	state := NewRuntimeState()
	if err := ConfigureSQLiteRuntime0373(context.Background(), state, sqliteFailBackend0373{}, sqliteTestSecret0373); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("failed commit reported success")
			}
		}()
		state.Security.setEmailVerified("u", true)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("poisoned store became available")
			}
		}()
		_ = state.Security.totpEnabled("u")
	}()
}

type sqliteFailBackend0373 struct{}

func (sqliteFailBackend0373) ReadRuntimeComponent0373(context.Context, string) ([]byte, bool, error) {
	return nil, false, nil
}
func (sqliteFailBackend0373) WriteRuntimeComponent0373(context.Context, string, []byte) error {
	return errors.New("disk full")
}
