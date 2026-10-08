package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func handleExtensionLifecycle0204(command string, args []string) error {
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("extension lifecycle требует --backend <url>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("extension lifecycle требует --token или NEVERLAUNCHER_TOKEN")
	}
	out := flagValue(args, "--output", "")
	scope := strings.TrimSpace(flagValue(args, "--scope", "global"))
	scopeID := strings.TrimSpace(flagValue(args, "--scope-id", ""))
	scopePayload := map[string]any{"scope": scope, "scopeId": scopeID}
	switch command {
	case "installed", "installations":
		values := url.Values{}
		if scope != "" {
			values.Set("scope", scope)
		}
		if scopeID != "" {
			values.Set("scopeId", scopeID)
		}
		endpoint := backend + "/api/v1/admin/extension-installs"
		if q := values.Encode(); q != "" {
			endpoint += "?" + q
		}
		payload, err := httpJSONWithAuth(http.MethodGet, endpoint, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "status":
		if len(args) < 1 || strings.HasPrefix(args[0], "--") {
			return errors.New("extension status требует extension id")
		}
		values := url.Values{}
		values.Set("scope", scope)
		if scopeID != "" {
			values.Set("scopeId", scopeID)
		}
		endpoint := backend + "/api/v1/admin/extension-installs/" + url.PathEscape(args[0]) + "?" + values.Encode()
		payload, err := httpJSONWithAuth(http.MethodGet, endpoint, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "install":
		if len(args) < 1 || strings.HasPrefix(args[0], "--") {
			return errors.New("extension install требует id@version")
		}
		id, versionValue, ok := parseRegistryCoordinate0203(args[0])
		if !ok {
			return errors.New("extension install требует координату id@version")
		}
		scopePayload["version"] = versionValue
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-installs/"+url.PathEscape(id)+"/install", scopePayload, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "enable", "disable", "uninstall", "rollback":
		if len(args) < 1 || strings.HasPrefix(args[0], "--") {
			return fmt.Errorf("extension %s требует extension id", command)
		}
		id := args[0]
		if parsed, _, ok := parseRegistryCoordinate0203(id); ok {
			id = parsed
		}
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-installs/"+url.PathEscape(id)+"/"+command, scopePayload, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "update":
		if len(args) < 1 || strings.HasPrefix(args[0], "--") {
			return errors.New("extension update требует extension id или id@version")
		}
		id, versionValue, hasVersion := parseRegistryCoordinate0203(args[0])
		if !hasVersion {
			id = args[0]
			versionValue = strings.TrimSpace(flagValue(args, "--version", ""))
		}
		channel := strings.TrimSpace(flagValue(args, "--channel", ""))
		if versionValue == "" && channel == "" {
			channel = "stable"
		}
		if versionValue != "" {
			scopePayload["version"] = versionValue
		}
		if channel != "" {
			scopePayload["channel"] = channel
		}
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-installs/"+url.PathEscape(id)+"/update", scopePayload, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	default:
		return fmt.Errorf("неизвестная extension lifecycle-подкоманда: %s", command)
	}
}
