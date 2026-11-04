package httpapi

import "net/http"

// Every API response, including errors, carries the independently versioned v1 contract.
func withAPIContract04512(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Launcher-API-Contract", "1.0.0")
		next.ServeHTTP(w, r)
	})
}
