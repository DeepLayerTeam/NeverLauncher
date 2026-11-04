package main

import (
	"errors"
	"net/http"
	"strings"
)

// Список расширений оператора формируется работающим Backend, а не из локального
// кэша манифестов. Он содержит текущее состояние JVM, действующие права и последние
// журналы Runtime. Сервер проверяет extension:manage при каждом запросе.
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
