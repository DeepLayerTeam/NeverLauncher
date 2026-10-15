package httpapi

import (
	"net/http"
	"strings"
	"sync"
)

// maintenanceGate сериализует разрушающие операции резервирования и восстановления
// относительно всех изменений API. Изменяющие запросы держат блокировку чтения весь срок
// жизни; обработчики backup/restore берут блокировку записи перед работой с БД и хранилищем.
type maintenanceGate struct {
	mu sync.RWMutex
}

func (g *maintenanceGate) withMutationLock(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || !isMutationRequest(r) || isMaintenanceOperation(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		g.mu.RLock()
		defer g.mu.RUnlock()
		next.ServeHTTP(w, r)
	})
}

func isMutationRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isMaintenanceOperation(path string) bool {
	path = strings.TrimSpace(path)
	return path == "/api/v1/operations/backups" || strings.HasPrefix(path, "/api/v1/operations/backups/") || path == "/api/v1/operations/migrations/apply"
}

func (s Server) beginMaintenanceExclusive() func() {
	if s.State == nil || s.State.Maintenance == nil {
		return func() {}
	}
	s.State.Maintenance.mu.Lock()
	return s.State.Maintenance.mu.Unlock
}
