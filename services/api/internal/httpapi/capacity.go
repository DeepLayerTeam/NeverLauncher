package httpapi

import "net/http"

// Для просмотра эксплуатационных параметров ёмкости требуется действующее право
// diagnostics:read. Никогда не возвращайте строки подключения, ключи объектов или
// серверные пути.
func (s Server) operationsCapacity03215(w http.ResponseWriter, r *http.Request) {
	if s.Capacity == nil {
		writeError(w, http.StatusServiceUnavailable, "Сборщик метрик ёмкости не инициализирован")
		return
	}
	report := s.Capacity.Latest()
	if !report.Verified {
		writeJSON(w, http.StatusServiceUnavailable, report)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
