package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
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
	path := filepath.Join(privateSQLiteTempDir(t), "launcher.db")
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
		t.Fatalf("ошибка создания токена: %v", err)
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
		t.Fatalf("Отсутствует шифротекст безопасности или раскрыт секрет: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, state = openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	defer repo.Close()
	if _, ok := state.AuthSessions.get(session.ID, user.ID); !ok {
		t.Fatal("Сессия потеряна")
	}
	if !state.Security.totpEnabled(user.ID) {
		t.Fatal("Многофакторная аутентификация не восстановлена")
	}
	if !state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("Потерян код восстановления")
	}
	if state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("Повторно использован код восстановления")
	}
	if _, ok := state.Security.consumeOneTimeToken(token, "password-reset"); !ok {
		t.Fatal("Потерян токен сброса пароля")
	}
	if _, err := state.Passkeys.consumeChallenge(challengeToken, "register"); err != nil {
		t.Fatalf("Запрос подтверждения потерян: %v", err)
	}
	if _, err := state.Passkeys.credentialByRawID(cred.CredentialID); err != nil {
		t.Fatal(err)
	}
	if state.ServerBridge.servers["node-1"].TokenHash != "bridge-token-hash" {
		t.Fatal("Потерян хеш идентичности моста")
	}
	if _, ok := state.ServerBridge.nodeNonces["nonce-hash"]; !ok {
		t.Fatal("Потеряно одноразовое значение защиты моста от повторного воспроизведения")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, state = openSQLiteRuntimeTest0373(t, path, sqliteTestSecret0373)
	defer repo.Close()
	if state.Security.consumeRecoveryCode(user.ID, code) {
		t.Fatal("Код восстановления повторно использован после перезапуска")
	}
	if _, ok := state.Security.consumeOneTimeToken(token, "password-reset"); ok {
		t.Fatal("Повторно использован токен сброса пароля после перезапуска")
	}
	if _, err := state.Passkeys.consumeChallenge(challengeToken, "register"); err == nil {
		t.Fatal("Повторно использован запрос WebAuthn после перезапуска")
	}
	if _, next, err := state.AuthSessions.rotate(refresh); err != nil || next == "" {
		t.Fatalf("Токен обновления потерян после перезапуска: %v", err)
	}
	if _, _, err := state.AuthSessions.rotate(refresh); !errors.Is(err, errRefreshTokenReuseDetected) {
		t.Fatalf("Повторное использование токена обновления не обнаружено: %v", err)
	}
}
func TestSQLiteRuntimeRejectsWrongKey0373(t *testing.T) {
	path := filepath.Join(privateSQLiteTempDir(t), "launcher.db")
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
		t.Fatal("Неверный ключ расшифрования должен приводить к отказу")
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
				t.Error("Неудачная фиксация изменений объявлена успешной")
			}
		}()
		state.Security.setEmailVerified("u", true)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Повреждённое хранилище стало доступно")
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
	return errors.New("на диске нет свободного места")
}
