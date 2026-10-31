package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"net/http"
	"strings"
	"time"
)

// playerComponentPermissions0392 returns only permissions granted by the
// authoritative project role for the exact published, signed catalog.
// Callers cannot submit their own grant list, and responses are never cached.
func (s Server) playerComponentPermissions0392(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	projectID, profileID := r.PathValue("projectId"), r.PathValue("profileId")
	channel := r.URL.Query().Get("channel")
	digest := r.URL.Query().Get("catalogDigest")
	if projectID == "" || profileID == "" || channel == "" || len(channel) > 128 || len(digest) != 64 ||
		strings.ContainsAny(channel, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "invalid component scope")
		return
	}
	if !s.authorizeClaims(r, claims, "profile:download", projectID, "profile", profileID).Allowed {
		writeError(w, http.StatusForbidden, "profile download denied")
		return
	}
	manifest, err := s.Repo.GetManifest(projectID, profileID, channel)
	if err != nil || manifest.SchemaVersion != model.ManifestSchemaV3 || manifest.ComponentCatalog == nil ||
		!strings.EqualFold(manifest.ComponentCatalog.Digest, digest) || s.verifyManifestSignature(manifest) != nil {
		writeError(w, http.StatusNotFound, "signed component catalog not available")
		return
	}
	permissions := make([]string, 0)
	encountered := map[string]bool{}
	for _, c := range manifest.ComponentCatalog.Components {
		if c.Conditions == nil {
			continue
		}
		for _, name := range c.Conditions.Permissions {
			if encountered[name] {
				continue
			}
			encountered[name] = true
			// Translate signed condition names into a dedicated project role
			// namespace. "premium" -> "component.premium"; prefixed
			// names remain unchanged. A claim is never taken from the client.
			action := name
			if !strings.HasPrefix(action, "component.") {
				action = "component." + action
			}
			if s.authorizeClaims(r, claims, action, projectID, "profile", profileID).Allowed {
				permissions = append(permissions, name)
			}
		}
	}
	// Do not expose a grant outside the authenticated session's lifetime.
	validUntil := time.Now().UTC().Add(30 * time.Minute).Unix()
	if claims.Exp < validUntil {
		validUntil = claims.Exp
	}
	if validUntil <= time.Now().UTC().Unix() {
		writeError(w, http.StatusUnauthorized, "expired session")
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"projectId": projectID, "profileId": profileID, "channel": channel,
		"catalogDigest": manifest.ComponentCatalog.Digest, "subject": claims.Sub,
		"sessionId": claims.SessionID, "validUntil": validUntil, "permissions": permissions,
	})
}
