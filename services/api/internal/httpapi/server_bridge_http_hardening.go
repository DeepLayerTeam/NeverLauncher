package httpapi

import (
	"context"
	"net/http"
	"strings"
)

func isServerBridgeTraffic0149(r *http.Request) bool {
	path := r.URL.Path
	return strings.HasPrefix(path, "/api/v1/server-bridge/") || path == "/api/v1/session/has-joined"
}

func isServerBridgeMutation0149(r *http.Request) bool {
	if !isServerBridgeTraffic0149(r) {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

// withServerBridgeHardening0149 ограничивает срок запросов моста и размер
// тела независимо. Обработчики подписанных узлом запросов применяют тот
// же предел 64 КиБ при каноникализации тела для многослойной защиты.
func (s Server) withServerBridgeHardening0149(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isServerBridgeTraffic0149(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if isServerBridgeMutation0149(r) && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, serverBridgeNodeMaxBody0142)
		}
		ctx, cancel := context.WithTimeout(r.Context(), serverBridgeRequestTimeout0149)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
