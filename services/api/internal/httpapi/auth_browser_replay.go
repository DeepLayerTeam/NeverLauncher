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

// Зашифрованная браузерная транзакция — доказательство подлинности, а не
// одноразовые учётные данные. Захватывайте state атомарно ДО обмена кода
// авторизации, иначе повтор на другой реплике API сможет дважды привязать
// провайдера и при повторно используемом upstream-коде создать несколько сессий
// Launcher. ConsumeDurableNonce использует уникальный ключ PostgreSQL или общий
// дисковый координатор SQLite. Недоступное хранилище никогда не должно разрешать
// вход.
type browserNonceStore0525 interface {
	ConsumeDurableNonce(context.Context, string, string, string, map[string]any, time.Time) error
}

func (s Server) claimBrowserTransaction0525(w http.ResponseWriter, r *http.Request, tx oidcTransaction115) bool {
	store, ok := s.Repo.(browserNonceStore0525)
	if !ok || store == nil {
		writeError(w, http.StatusServiceUnavailable, "Постоянное хранилище защиты от повторного использования браузерной аутентификации недоступно")
		return false
	}
	if tx.ProviderID == "" || tx.State == "" || tx.ExpiresAt <= time.Now().UTC().Unix() {
		writeError(w, http.StatusUnauthorized, "Браузерная транзакция некорректна или срок её действия истёк")
		return false
	}
	// Одно и то же состояние нельзя поглотить через другую точку входа, режим привязки
	// или повторную запечатку зашифрованного конверта. Сырой state и code никогда не
	// сохраняются.
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
		writeError(w, http.StatusUnauthorized, "Браузерная транзакция уже использована")
	} else {
		writeError(w, http.StatusServiceUnavailable, "Хранилище защиты от повторного выполнения браузерной транзакции недоступно")
	}
	return false
}
