package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type migrationSecurityStore0336 interface {
	ResetMigrationTrust0336(context.Context, string, string, string, bool) (repository.MigrationSecurityReport0336, error)
	GetMigrationSecurity0336(context.Context, string) (repository.MigrationSecurityReport0336, error)
}

// Требуйте явно выделенных независимых подписантов Launcher Runtime. Это НЕ
// означает, что разделение ключей доказуемо сравнением имён или KID: оператор
// должен самостоятельно подготовить новые секреты и отдельно подтвердить это.
func migrationSigner0336(cfg config.Config) (string, string, error) {
	kid := strings.TrimSpace(cfg.AuthTokenActiveKID)
	if kid == "" || len(kid) > 96 {
		return "", "", errors.New("Требуется: «явно указанный активный KID JWT Launcher»")
	}
	keys := map[string]string{}
	if err := json.Unmarshal([]byte(cfg.AuthTokenKeysJSON), &keys); err != nil {
		return "", "", errors.New("Требуется: «явно указанный набор ключей JWT Launcher»")
	}
	active := strings.TrimSpace(keys[kid])
	if len(active) < 32 {
		return "", "", errors.New("active Launcher JWT secret: требуется «создан независимо (не менее 32 байт)»")
	}
	for other, name := range keys {
		if other != kid && name == active {
			return "", "", errors.New("Один ключ JWT используется под несколькими идентификаторами")
		}
	}
	if strings.EqualFold(active, strings.TrimSpace(cfg.ManifestSigningPrivateKey)) {
		return "", "", errors.New("Секрет JWT и ключ подписи Ed25519 должны быть независимыми")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(cfg.ManifestSigningPrivateKey))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", "", errors.New("необходимо настроить исходное значение Ed25519 для подписи нового манифеста Launcher")
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	return kid, hex.EncodeToString(digest[:]), nil
}
func (s Server) registerMigrationSecurityRoutes0336(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/migration-runs/{runId}/security", s.requirePermission("settings:manage", s.migrationSecurityGet0336))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/security/preview", s.requirePermission("settings:manage", s.migrationSecurityPreview0336))
	mux.Handle("POST /api/v1/admin/migration-runs/{runId}/security/activate", s.requirePermission("settings:manage", s.migrationSecurityActivate0336))
}
func (s Server) migrationSecurityGet0336(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(migrationSecurityStore0336)
	if !ok {
		writeError(w, 503, "Для безопасной миграции требуется PostgreSQL")
		return
	}
	report, err := store.GetMigrationSecurity0336(r.Context(), r.PathValue("runId"))
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
func (s Server) migrationSecurityPreview0336(w http.ResponseWriter, r *http.Request) {
	s.migrationSecurityApply0336(w, r, true)
}
func (s Server) migrationSecurityActivate0336(w http.ResponseWriter, r *http.Request) {
	s.migrationSecurityApply0336(w, r, false)
}
func (s Server) migrationSecurityApply0336(w http.ResponseWriter, r *http.Request, preview bool) {
	store, ok := s.Repo.(migrationSecurityStore0336)
	if !ok {
		writeError(w, 503, "Для безопасной миграции требуется PostgreSQL")
		return
	}
	// Клиент не может предоставлять пользователей, ID сеансов, ключевой материал,
	// старые доверенные корни или сопоставления учётных записей. Цели операции
	// выводятся из зафиксированной квитанции MIG05.
	if r.ContentLength > 0 {
		writeError(w, 400, "Запрос сброса безопасности не допускает тело")
		return
	}
	runID := r.PathValue("runId")
	if !preview {
		if r.Header.Get("X-Migration-Trust-Confirm") != runID || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
			writeError(w, 400, "Требуется подтверждение запуска и подтверждение независимо подготовленных ключей Launcher")
			return
		}
	}
	kid, pub, err := migrationSigner0336(s.Config)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	report, err := store.ResetMigrationTrust0336(r.Context(), runID, kid, pub, preview)
	if err != nil {
		migrationHTTPError0331(w, err)
		return
	}
	if !preview {
		s.audit(r, s.adminActor(r), "migration:gravit-security-reset", runID)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": report})
}
