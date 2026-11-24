package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/aigateway"
)

func (s Server) registerAIRoutes121(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/ai/responses", s.aiResponses121)
	mux.HandleFunc("GET /api/v1/ai/usage", s.aiUsage121)
	mux.Handle("GET /api/v1/admin/ai/usage", s.requirePermission("users:manage", s.aiAdminUsage121))
}
func (s Server) aiClaims121(w http.ResponseWriter, r *http.Request) (authClaims, bool) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, 401, "Требуется действительная сессия")
		return claims, false
	}
	if s.AI == nil {
		writeError(w, 503, "AI отключён")
		return claims, false
	}
	if !s.AI.Allowed(claims.RoleID) {
		writeError(w, 403, "Доступ к AI запрещён")
		return claims, false
	}
	return claims, true
}
func (s Server) aiUsage121(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.aiClaims121(w, r)
	if !ok {
		return
	}
	s.aiWriteUsage121(w, r, claims.Sub)
}
func (s Server) aiAdminUsage121(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.AI == nil {
		writeError(w, 503, "AI отключён")
		return
	}
	s.aiWriteUsage121(w, r, "")
}
func (s Server) aiWriteUsage121(w http.ResponseWriter, r *http.Request, user string) {
	u, err := s.AI.Usage(r.Context(), user)
	if err != nil {
		writeError(w, 503, "Учёт расходов недоступен")
		return
	}
	writeJSON(w, 200, map[string]any{"model": s.AI.Model(), "month": time.Now().UTC().Format("2006-01"), "budgetMicroUsd": s.AI.Budget(user != ""), "usage": u})
}
func (s Server) aiResponses121(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.aiClaims121(w, r)
	if !ok {
		return
	}
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		writeError(w, 400, "Ожидается application/json")
		return
	}
	controller := http.NewResponseController(w)
	// Bound slow clients before reading or streaming; some wrappers expose Unwrap.
	if err := controller.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(w, 503, "AI недоступен")
		return
	}
	defer controller.SetReadDeadline(time.Time{})
	p, err := aigateway.DecodeRequest(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		writeError(w, 400, "Некорректный prompt")
		return
	}
	_ = controller.SetReadDeadline(time.Time{})
	started := false
	emit := func(event string, data aigateway.Event) error {
		if !started {
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store, no-transform")
			w.Header().Set("X-Accel-Buffering", "no")
			started = true
		}
		_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		defer controller.SetWriteDeadline(time.Time{})
		b, e := json.Marshal(data)
		if e != nil {
			return e
		}
		if _, e = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); e != nil {
			return e
		}
		return controller.Flush()
	}
	defer controller.SetWriteDeadline(time.Time{})
	check := func() bool {
		c, e := s.verifyAdminTokenFromRequest(r)
		return e == nil && c.Sub == claims.Sub && s.AI.Allowed(c.RoleID)
	}
	err = s.AI.Stream(r.Context(), claims.Sub, p, check, emit)
	if started {
		return
	}
	switch {
	case errors.Is(err, aigateway.ErrSensitive):
		writeError(w, 422, "Удалите возможные секреты из запроса AI")
	case errors.Is(err, aigateway.ErrCoolingDown):
		w.Header().Set("Retry-After", "30")
		writeError(w, 503, "AI временно недоступен")
	case errors.Is(err, aigateway.ErrInvalid):
		writeError(w, 400, "Prompt превышает допустимый размер")
	case errors.Is(err, aigateway.ErrAccess):
		writeError(w, 403, "Доступ к AI запрещён")
	case errors.Is(err, aigateway.ErrBudget):
		writeError(w, 429, "Месячный бюджет AI исчерпан")
	case errors.Is(err, aigateway.ErrRate), errors.Is(err, aigateway.ErrBusy):
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "Лимит запросов AI")
	default:
		writeError(w, 503, "AI временно недоступен")
	}
}
