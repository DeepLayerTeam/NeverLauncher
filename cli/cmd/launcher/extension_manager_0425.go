package main

import (
	"errors"
	"net/http"
	"strings"
)

// The operator inventory is built by the running Backend, not from locally
// cached manifests. It includes current JVM state, effective permissions and
// recent runtime logs. The server checks extension:manage for every request.
func handleExtensionManager0425(args []string) error {
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("extension manager требует --backend <url>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("extension manager требует --token или LAUNCHER_TOKEN")
	}
	out := strings.TrimSpace(flagValue(args, "--output", ""))
	payload, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extensions/manager", nil, token)
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}
