package httpapi

import (
	"net/http"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
)

func (s Server) extensionGAStatus0210(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionGA == nil {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions GA manager is unavailable")
		return
	}
	report, err := s.ExtensionGA.Validate(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := "healthy"
	if len(report.Issues) > 0 {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": apiContractVersion,
		"data":       map[string]any{"status": status, "safeMode": s.ExtensionSafeMode, "contract": extensioncontract.Frozen(), "report": report},
	})
}

func (s Server) extensionGAReconcile0210(w http.ResponseWriter, r *http.Request) {
	if s.ExtensionGA == nil {
		writeError(w, http.StatusServiceUnavailable, "NeverExtensions GA manager is unavailable")
		return
	}
	report, err := s.ExtensionGA.Reconcile(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Reconcile the process layer after invalid extensions were fail-closed.
	hostErrors := []string{}
	if s.ExtensionHost != nil && !s.ExtensionSafeMode {
		for _, e := range s.ExtensionHost.Reconcile(r.Context()) {
			if e != nil {
				hostErrors = append(hostErrors, e.Error())
			}
		}
	}
	s.audit(r, s.adminActor(r), "extension:ga:reconcile", "checked="+itoa0210(report.Checked)+";disabled="+itoa0210(report.Disabled))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"report": report, "hostErrors": hostErrors}})
}

func itoa0210(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [32]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
