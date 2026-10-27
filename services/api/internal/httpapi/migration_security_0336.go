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

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type migrationSecurityStore0336 interface {
	ResetMigrationTrust0336(context.Context, string, string, string, bool) (repository.MigrationSecurityReport0336, error)
	GetMigrationSecurity0336(context.Context, string) (repository.MigrationSecurityReport0336, error)
}

// Require explicit, independently-provisioned Never runtime signers. This is
// NOT a claim that key separation can be proven by comparing names or KIDs:
// the operator must provision fresh secrets and confirm that separately.
func migrationSigner0336(cfg config.Config) (string, string, error) {
	kid := strings.TrimSpace(cfg.AuthTokenActiveKID)
	if kid == "" || len(kid) > 96 {
		return "", "", errors.New("explicit Never JWT active KID required")
	}
	keys := map[string]string{}
	if err := json.Unmarshal([]byte(cfg.AuthTokenKeysJSON), &keys); err != nil {
		return "", "", errors.New("explicit Never JWT key set required")
	}
	active := strings.TrimSpace(keys[kid])
	if len(active) < 32 {
		return "", "", errors.New("active Never JWT secret must be independently provisioned (min 32 bytes)")
	}
	for other, name := range keys {
		if other != kid && name == active {
			return "", "", errors.New("JWT key reused under multiple key IDs")
		}
	}
	if strings.EqualFold(active, strings.TrimSpace(cfg.ManifestSigningPrivateKey)) {
		return "", "", errors.New("JWT and Ed25519 signing secrets must be independent")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(cfg.ManifestSigningPrivateKey))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", "", errors.New("new Never Ed25519 manifest signing seed must be configured")
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
		writeError(w, 503, "migration security requires PostgreSQL")
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
		writeError(w, 503, "migration security requires PostgreSQL")
		return
	}
	// No client-supplied users, session IDs, key material, old trust anchors or
	// account mapping. Operation derives targets from the committed MIG05 receipt.
	if r.ContentLength > 0 {
		writeError(w, 400, "security reset does not accept a request body")
		return
	}
	runID := r.PathValue("runId")
	if !preview {
		if r.Header.Get("X-Migration-Trust-Confirm") != runID || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
			writeError(w, 400, "explicit run confirmation and independently provisioned Never keys acknowledgement required")
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
