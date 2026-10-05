package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func handleExtensionHost0205(args []string) error {
	if len(args) == 0 {
		return errors.New("extension host требует подкоманду: list, status, logs, start, stop, restart")
	}
	command := strings.ToLower(strings.TrimSpace(args[0]))
	args = args[1:]
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("extension host требует --backend <url>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("extension host требует --token или NEVERLAUNCHER_TOKEN")
	}
	out := flagValue(args, "--output", "")
	scope := strings.TrimSpace(flagValue(args, "--scope", "global"))
	scopeID := strings.TrimSpace(flagValue(args, "--scope-id", ""))
	query := url.Values{}
	query.Set("scope", scope)
	if scopeID != "" {
		query.Set("scopeId", scopeID)
	}
	switch command {
	case "list":
		payload, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-hosts", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "status", "logs", "start", "stop", "restart":
		if len(args) < 1 || strings.HasPrefix(args[0], "--") {
			return fmt.Errorf("extension host %s требует extension id", command)
		}
		id := url.PathEscape(strings.TrimSpace(args[0]))
		endpoint := backend + "/api/v1/admin/extension-hosts/" + id
		method := http.MethodGet
		if command == "logs" {
			endpoint += "/logs"
			limit := strings.TrimSpace(flagValue(args, "--limit", ""))
			if limit != "" {
				if _, err := strconv.Atoi(limit); err != nil {
					return errors.New("--limit должен быть числом")
				}
				query.Set("limit", limit)
			}
		} else if command != "status" {
			endpoint += "/" + command
			method = http.MethodPost
		}
		if encoded := query.Encode(); encoded != "" {
			endpoint += "?" + encoded
		}
		payload, err := httpJSONWithAuth(method, endpoint, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	default:
		return fmt.Errorf("неизвестная extension host подкоманда: %s", command)
	}
}
