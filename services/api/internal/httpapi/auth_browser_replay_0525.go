package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// The encrypted browser transaction is an authenticity proof, not a single-use
// credential. Claim its state atomically BEFORE exchanging the authorization
// code: otherwise replay on a different API replica can link a provider twice
// (and a fixture/reused upstream code may create multiple Never sessions).
// ConsumeDurableNonce uses PostgreSQL's unique key, or the shared on-disk
// SQLite coordinator. An unavailable store must never allow login.
type browserNonceStore0525 interface {
	ConsumeDurableNonce(context.Context, string, string, string, map[string]any, time.Time) error
}

func (s Server) claimBrowserTransaction0525(w http.ResponseWriter, r *http.Request, tx oidcTransaction115) bool {
	store, ok := s.Repo.(browserNonceStore0525)
	if !ok || store == nil {
		writeError(w, http.StatusServiceUnavailable, "durable browser authentication replay protection unavailable")
		return false
	}
	if tx.ProviderID == "" || tx.State == "" || tx.ExpiresAt <= time.Now().UTC().Unix() {
		writeError(w, http.StatusUnauthorized, "browser transaction invalid or expired")
		return false
	}
	// Exactly the same state cannot be consumed through another endpoint,
	// link mode or encrypted-envelope re-sealing. Never persist raw state or code.
	digest := sha256.Sum256([]byte(strings.ToLower(tx.ProviderID) + "\x00" + tx.State))
	kind := "login"
	if tx.LinkUserID != "" {
		kind = "link"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := store.ConsumeDurableNonce(ctx, "browser-oidc-0525", hex.EncodeToString(digest[:]),
		tx.LinkUserID, map[string]any{"provider": tx.ProviderID, "kind": kind}, time.Unix(tx.ExpiresAt, 0).UTC())
	if err == nil {
		return true
	}
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusUnauthorized, "browser transaction already used")
	} else {
		writeError(w, http.StatusServiceUnavailable, "browser transaction replay store unavailable")
	}
	return false
}
