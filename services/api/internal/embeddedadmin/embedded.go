// Package embeddedadmin provides the minimal same-origin production Admin and
// first-run wizard without requiring a separately deployed web server.
package embeddedadmin

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed site/*
var assets embed.FS

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := ""
		switch r.URL.Path {
		case "/admin", "/admin/":
			name = "site/index.html"
		case "/admin/app.js":
			name = "site/app.js"
		case "/admin/app.css":
			name = "site/app.css"
		default:
			http.NotFound(w, r)
			return
		}
		b, err := assets.ReadFile(name)
		if err != nil {
			http.Error(w, "embedded admin resource unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// No inline scripts, external network resources, frames or form forwarding.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if strings.HasSuffix(name, ".html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if strings.HasSuffix(name, ".js") {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	})
}
