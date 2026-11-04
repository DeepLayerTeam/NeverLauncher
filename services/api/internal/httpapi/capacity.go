package httpapi

import "net/http"

// Operational capacity details require the existing diagnostics:read permission.
// Never return connection strings, object keys or server paths.
func (s Server) operationsCapacity03215(w http.ResponseWriter, r *http.Request) {
	if s.Capacity == nil {
		writeError(w, http.StatusServiceUnavailable, "capacity collector not initialized")
		return
	}
	report := s.Capacity.Latest()
	if !report.Verified {
		writeJSON(w, http.StatusServiceUnavailable, report)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
