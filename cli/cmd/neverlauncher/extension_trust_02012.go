package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func extensionTrustBackend02012(args []string) (string, string, error) {
	backend := adminBackendURL(args)
	if backend == "" {
		return "", "", errors.New("расширение trust/recovery требует --серверная часть <URL>")
	}
	token := backendToken(args)
	if token == "" {
		return "", "", errors.New("расширение trust/recovery требует --токен или NEVERLAUNCHER_TOKEN")
	}
	return backend, token, nil
}

func responseDataField02012(payload map[string]any, field string) (any, error) {
	data, ok := payload["data"].(map[string]any)
	if !ok {
		return nil, errors.New("серверная часть ответ делает не contain данные объект")
	}
	value, ok := data[field]
	if !ok {
		return nil, fmt.Errorf("серверная часть ответ делает не contain данные.%s", field)
	}
	return value, nil
}

func handleExtensionTrust02012(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные расширение trust-подкоманды: показывать, задать, ключ-отзыв")
	}
	backend, token, err := extensionTrustBackend02012(args)
	if err != nil {
		return err
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "show":
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-trust/policy", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "set":
		mode := strings.ToLower(strings.TrimSpace(flagValue(args, "--mode", "strict")))
		if mode != "strict" && mode != "audit" {
			return errors.New("--режим должен быть строгий или аудит")
		}
		allowed := []string{}
		for _, item := range strings.Split(flagValue(args, "--allow", ""), ",") {
			if v := strings.ToLower(strings.TrimSpace(item)); v != "" {
				allowed = append(allowed, v)
			}
		}
		p, err := httpJSONWithAuth(http.MethodPut, backend+"/api/v1/admin/extension-trust/policy", map[string]any{"mode": mode, "allowedPublishers": allowed}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "key-revoke":
		publisher := strings.TrimSpace(flagValue(args, "--publisher", ""))
		fingerprint := strings.TrimSpace(flagValue(args, "--fingerprint", ""))
		if publisher == "" || fingerprint == "" {
			return errors.New("доверие ключ-отзыв требует --издатель <ID> --отпечаток <sha256:...>")
		}
		p, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-registry/publishers/"+url.PathEscape(publisher)+"/keys/"+url.PathEscape(fingerprint)+"/revoke", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	default:
		return fmt.Errorf("неизвестная расширение trust-подкоманда: %s", args[0])
	}
}

func handleExtensionQuarantine02012(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные расширение quarantine-подкоманды: список, релиз")
	}
	backend, token, err := extensionTrustBackend02012(args)
	if err != nil {
		return err
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "list":
		active := "true"
		if hasArg02012(args, "--all") {
			active = "false"
		}
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-quarantine?active="+active, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "release":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("карантин релиз требует карантин ID")
		}
		p, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-quarantine/"+url.PathEscape(args[1])+"/release", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	default:
		return fmt.Errorf("неизвестная расширение quarantine-подкоманда: %s", args[0])
	}
}

func handleExtensionEmergency02012(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные расширение emergency-подкоманды: список, отключить, clear")
	}
	backend, token, err := extensionTrustBackend02012(args)
	if err != nil {
		return err
	}
	out := flagValue(args, "--output", "")
	scope := strings.TrimSpace(flagValue(args, "--scope", "global"))
	scopeID := strings.TrimSpace(flagValue(args, "--scope-id", ""))
	switch args[0] {
	case "list":
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-emergency-disables", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "disable":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("аварийный отключить требует расширение ID")
		}
		reason := strings.TrimSpace(flagValue(args, "--reason", ""))
		if reason == "" {
			return errors.New("аварийный отключить требует --reason")
		}
		p, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extensions/"+url.PathEscape(args[1])+"/emergency-disable", map[string]any{"scope": scope, "scopeId": scopeID, "reason": reason}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "clear":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("аварийный clear требует расширение ID")
		}
		q := url.Values{}
		q.Set("scope", scope)
		if scopeID != "" {
			q.Set("scopeId", scopeID)
		}
		p, err := httpJSONWithAuth(http.MethodDelete, backend+"/api/v1/admin/extensions/"+url.PathEscape(args[1])+"/emergency-disable?"+q.Encode(), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	default:
		return fmt.Errorf("неизвестная расширение emergency-подкоманда: %s", args[0])
	}
}

func handleExtensionRecovery02012(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные расширение recovery-подкоманды: экспорт, импорт, резервное копирование, восстановление")
	}
	backend, token, err := extensionTrustBackend02012(args)
	if err != nil {
		return err
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "export", "backup":
		method := http.MethodGet
		field := "state"
		if args[0] == "backup" {
			method = http.MethodPost
			field = "backup"
		}
		p, err := httpJSONWithAuth(method, backend+"/api/v1/admin/extension-recovery/"+args[0], map[string]any{}, token)
		if err != nil {
			return err
		}
		value, err := responseDataField02012(p, field)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, value)
	case "import", "restore":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return fmt.Errorf("восстановление %s требует путь к JSON", args[0])
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("недопустимый восстановление JSON: %w", err)
		}
		body := value
		if args[0] == "import" {
			body = map[string]any{"state": value}
		}
		p, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-recovery/"+args[0], body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	default:
		return fmt.Errorf("неизвестная расширение recovery-подкоманда: %s", args[0])
	}
}

func hasArg02012(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}
