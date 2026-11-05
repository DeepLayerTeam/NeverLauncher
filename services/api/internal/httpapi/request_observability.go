package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Корреляционный идентификатор запроса всегда создаётся сервером: клиентскому
// X-Correlation-ID доверять нельзя, он не должен отравлять аудит. В журналы не пишутся
// URL, параметры запроса, заголовки, тела, пользователи или удалённые IP.
var accessLogger0459 = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

type observedResponse0459 struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (o *observedResponse0459) WriteHeader(code int) {
	if o.wrote {
		return
	}
	o.status = code
	o.wrote = true
	o.ResponseWriter.WriteHeader(code)
}
func (o *observedResponse0459) Write(b []byte) (int, error) {
	if !o.wrote {
		o.WriteHeader(http.StatusOK)
	}
	return o.ResponseWriter.Write(b)
}
func (o *observedResponse0459) Unwrap() http.ResponseWriter { return o.ResponseWriter }
func (o *observedResponse0459) Flush() {
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Используйте ограниченный перечень категорий, а не идентификаторы маршрутов
// или ресурсов: это предотвращает случайные утечки и метрики с высокой
// кардинальностью.
func requestCategory0459(path string) string {
	switch {
	case path == "/health":
		return "health"
	case path == "/ready":
		return "ready"
	case path == "/metrics":
		return "metrics"
	case strings.HasPrefix(path, "/api/"):
		return "api"
	case strings.HasPrefix(path, "/admin"):
		return "admin"
	case strings.HasPrefix(path, "/storage/"):
		return "storage"
	default:
		return "other"
	}
}
func logRequests0459(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newCorrelation02111()
		if id == "" {
			http.Error(w, "Недоступно: «correlation entropy»", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Correlation-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), correlationKey02111{}, id))
		start := time.Now()
		o := &observedResponse0459{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if v := recover(); v != nil {
				accessLogger0459.Error("http_panic", "correlation_id", id, "route_group", requestCategory0459(r.URL.Path))
				panic(v)
			}
			if r.URL.Path == "/metrics" || r.URL.Path == "/health" {
				return
			}
			accessLogger0459.Info("http_request", "correlation_id", id,
				"method", r.Method, "route_group", requestCategory0459(r.URL.Path),
				"status", o.status, "duration_ms", float64(time.Since(start).Microseconds())/1000)
		}()
		next.ServeHTTP(o, r)
	})
}
