package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func handleExtensionSecurity0207(command string, args []string) error {
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("расширение безопасность требует --серверная часть <URL>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("расширение безопасность требует --токен или NEVERLAUNCHER_TOKEN")
	}
	out := flagValue(args, "--output", "")
	if command == "capabilities" {
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-capabilities", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	}
	if len(args) < 1 || strings.HasPrefix(args[0], "--") {
		return fmt.Errorf("расширение %s требует расширение ID", command)
	}
	id := args[0]
	scope := flagValue(args, "--scope", "global")
	scopeID := flagValue(args, "--scope-id", "")
	q := url.Values{}
	q.Set("scope", scope)
	if scopeID != "" {
		q.Set("scopeId", scopeID)
	}
	switch command {
	case "permissions":
		if v := flagValue(args, "--version", ""); v != "" {
			q.Set("version", v)
		}
		if v := flagValue(args, "--from-version", ""); v != "" {
			q.Set("fromVersion", v)
		}
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/permissions?"+q.Encode(), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "permission-grant":
		permission := strings.TrimSpace(flagValue(args, "--permission", ""))
		if permission == "" {
			return errors.New("разрешение-grant требует --разрешение")
		}
		body := map[string]any{"scope": scope, "scopeId": scopeID, "permission": permission, "reason": flagValue(args, "--reason", "")}
		if v := flagValue(args, "--version", ""); v != "" {
			body["version"] = v
		}
		p, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/permissions", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "permission-revoke":
		permission := strings.TrimSpace(flagValue(args, "--permission", ""))
		if permission == "" {
			return errors.New("разрешение-отзыв требует --разрешение")
		}
		_, err := httpJSONWithAuth(http.MethodDelete, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/permissions/"+url.PathEscape(permission)+"?"+q.Encode(), nil, token)
		return err
	case "secrets":
		p, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/secrets?"+q.Encode(), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "secret-set":
		name := strings.TrimSpace(flagValue(args, "--name", ""))
		if name == "" {
			return errors.New("секрет-задать требует --имя")
		}
		var value []byte
		var err error
		if path := flagValue(args, "--value-file", ""); path != "" {
			value, err = os.ReadFile(path)
		} else if hasFlag0207(args, "--stdin") {
			value, err = io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
		} else if v := os.Getenv("NEVERLAUNCHER_EXTENSION_SECRET_VALUE"); v != "" {
			value = []byte(v)
		} else {
			return errors.New("секрет-задать требует --value-файл, --стандартный ввод или NEVERLAUNCHER_EXTENSION_SECRET_VALUE")
		}
		if err != nil {
			return err
		}
		if len(value) > 1<<20 {
			return errors.New("секрет value exceeds 1 MiB")
		}
		body := map[string]any{"scope": scope, "scopeId": scopeID, "valueBase64": base64.StdEncoding.EncodeToString(value)}
		for i := range value {
			value[i] = 0
		}
		p, err := httpJSONWithAuth(http.MethodPut, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/secrets/"+url.PathEscape(name), body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, p)
	case "secret-delete":
		name := strings.TrimSpace(flagValue(args, "--name", ""))
		if name == "" {
			return errors.New("секрет-удалять требует --имя")
		}
		_, err := httpJSONWithAuth(http.MethodDelete, backend+"/api/v1/admin/extensions/"+url.PathEscape(id)+"/secrets/"+url.PathEscape(name)+"?"+q.Encode(), nil, token)
		return err
	default:
		return fmt.Errorf("неизвестная расширение security-подкоманда: %s", command)
	}
}
func hasFlag0207(args []string, name string) bool {
	for _, v := range args {
		if v == name {
			return true
		}
	}
	return false
}
