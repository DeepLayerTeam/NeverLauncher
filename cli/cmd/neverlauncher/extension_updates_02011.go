package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func handleExtensionUpdates02011(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные расширение updates-подкоманды: plan, применить, закрепляет, закреплять, unpin, транзакция")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("расширение обновляет требует --серверная часть <URL>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("расширение обновляет требует --токен или NEVERLAUNCHER_TOKEN")
	}
	out := flagValue(args, "--output", "")
	scope := strings.TrimSpace(flagValue(args, "--scope", "global"))
	scopeID := strings.TrimSpace(flagValue(args, "--scope-id", ""))
	switch args[0] {
	case "plan", "apply":
		roots := []map[string]any{}
		channel := strings.ToLower(strings.TrimSpace(flagValue(args, "--channel", "stable")))
		if channel != "stable" && channel != "beta" && channel != "dev" {
			return errors.New("--канал должен быть стабильный, beta или dev")
		}
		for _, raw := range args[1:] {
			if strings.HasPrefix(raw, "--") {
				break
			}
			id, v, ok := parseRegistryCoordinate0203(raw)
			root := map[string]any{"extensionId": id, "channel": channel}
			if ok {
				root["version"] = v
			}
			roots = append(roots, root)
		}
		payload := map[string]any{"scope": scope, "scopeId": scopeID, "channel": channel, "roots": roots}
		endpoint := backend + "/api/v1/admin/extension-updates/" + args[0]
		resp, err := httpJSONWithAuth(http.MethodPost, endpoint, payload, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, resp)
	case "pins":
		q := url.Values{}
		q.Set("scope", scope)
		if scopeID != "" {
			q.Set("scopeId", scopeID)
		}
		resp, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-updates/pins?"+q.Encode(), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, resp)
	case "pin":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("обновляет закреплять требует ID@версия")
		}
		id, v, ok := parseRegistryCoordinate0203(args[1])
		if !ok {
			return errors.New("обновляет закреплять требует ID@версия")
		}
		resp, err := httpJSONWithAuth(http.MethodPut, backend+"/api/v1/admin/extension-updates/pins/"+url.PathEscape(id), map[string]any{"scope": scope, "scopeId": scopeID, "version": v}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, resp)
	case "unpin":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("обновляет unpin требует расширение ID")
		}
		q := url.Values{}
		q.Set("scope", scope)
		if scopeID != "" {
			q.Set("scopeId", scopeID)
		}
		resp, err := httpJSONWithAuth(http.MethodDelete, backend+"/api/v1/admin/extension-updates/pins/"+url.PathEscape(args[1])+"?"+q.Encode(), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, resp)
	case "transaction":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("обновляет транзакция требует транзакция ID")
		}
		resp, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-updates/transactions/"+url.PathEscape(args[1]), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, resp)
	default:
		return fmt.Errorf("неизвестная расширение updates-подкоманда: %s", args[0])
	}
}
