package httpapi

import "net/http"

// Каждый ответ API, включая ошибки, несёт независимо версионированный контракт v1.
func withAPIContract04512(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Launcher-API-Contract", "1.0.0")
		next.ServeHTTP(w, r)
	})
}
