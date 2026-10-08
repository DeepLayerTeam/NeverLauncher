package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func handleExtensionRegistry0203(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные реестр расширений-подкоманды: издатели, издатель-добавлять, ключ-добавлять, ключи, search, список, показывать, публикация, yank, канал-задать, pull, установка")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("реестр расширений требует --серверная часть <URL>")
	}
	token := backendToken(args)
	if token == "" {
		return errors.New("реестр расширений требует --токен или NEVERLAUNCHER_TOKEN")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "publishers":
		payload, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-registry/publishers", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "publisher-add":
		id, name := strings.TrimSpace(flagValue(args, "--id", "")), strings.TrimSpace(flagValue(args, "--name", ""))
		if id == "" || name == "" {
			return errors.New("издатель-добавлять требует --ID и --имя")
		}
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-registry/publishers", map[string]any{"id": id, "name": name, "active": true}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "key-add":
		publisher, keyPath := strings.TrimSpace(flagValue(args, "--publisher", "")), strings.TrimSpace(flagValue(args, "--public-key", ""))
		if publisher == "" || keyPath == "" {
			return errors.New("ключ-добавлять требует --издатель и --публичный-ключ")
		}
		publicKey, err := loadEd25519PublicKey(keyPath)
		if err != nil {
			return err
		}
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-registry/publishers/"+url.PathEscape(publisher)+"/keys", map[string]any{"publicKeyBase64": base64.StdEncoding.EncodeToString(publicKey), "active": true}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "keys":
		publisher := strings.TrimSpace(flagValue(args, "--publisher", ""))
		if publisher == "" {
			return errors.New("ключи требует --издатель")
		}
		payload, err := httpJSONWithAuth(http.MethodGet, backend+"/api/v1/admin/extension-registry/publishers/"+url.PathEscape(publisher)+"/keys", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "search", "list":
		values := url.Values{}
		if args[0] == "search" {
			q := strings.TrimSpace(flagValue(args, "--query", flagValue(args, "--q", "")))
			if q == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
				q = args[1]
			}
			if q != "" {
				values.Set("q", q)
			}
		}
		for flag, query := range map[string]string{"--channel": "channel", "--launcher-version": "launcherVersion", "--os": "os", "--arch": "arch"} {
			if value := strings.TrimSpace(flagValue(args, flag, "")); value != "" {
				values.Set(query, value)
			}
		}
		if flagBool(args, "--include-yanked", false) {
			values.Set("includeYanked", "true")
		}
		endpoint := backend + "/api/v1/admin/extension-registry/extensions"
		if encoded := values.Encode(); encoded != "" {
			endpoint += "?" + encoded
		}
		payload, err := httpJSONWithAuth(http.MethodGet, endpoint, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "show":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("показывать требует расширение ID или ID@версия")
		}
		id, versionValue, hasVersion := parseRegistryCoordinate0203(args[1])
		endpoint := backend + "/api/v1/admin/extension-registry/extensions/" + url.PathEscape(id)
		if hasVersion {
			endpoint += "/versions/" + url.PathEscape(versionValue)
		}
		payload, err := httpJSONWithAuth(http.MethodGet, endpoint, nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "publish":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("публикация требует путь к подписанному.nlext")
		}
		return extensionRegistryPublishCLI0203(backend, token, args[1], args[2:], out)
	case "yank":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("yank требует ID@версия")
		}
		id, versionValue, ok := parseRegistryCoordinate0203(args[1])
		if !ok {
			return errors.New("yank требует координату ID@версия")
		}
		reason := strings.TrimSpace(flagValue(args, "--reason", ""))
		if reason == "" {
			return errors.New("yank требует --reason")
		}
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-registry/extensions/"+url.PathEscape(id)+"/versions/"+url.PathEscape(versionValue)+"/yank", map[string]any{"reason": reason}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "channel-set":
		id, channel, versionValue := strings.TrimSpace(flagValue(args, "--id", "")), strings.TrimSpace(flagValue(args, "--channel", "")), strings.TrimSpace(flagValue(args, "--version", ""))
		if id == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			id = args[1]
		}
		if id == "" || channel == "" || versionValue == "" {
			return errors.New("канал-задать требует расширение ID, --канал и --версия")
		}
		payload, err := httpJSONWithAuth(http.MethodPut, backend+"/api/v1/admin/extension-registry/extensions/"+url.PathEscape(id)+"/channels/"+url.PathEscape(channel), map[string]any{"version": versionValue}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "pull":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("pull требует ID@версия")
		}
		id, versionValue, ok := parseRegistryCoordinate0203(args[1])
		if !ok {
			return errors.New("pull требует координату ID@версия")
		}
		dest := strings.TrimSpace(flagValue(args, "--output", id+"-"+versionValue+".nlext"))
		return extensionRegistryPullCLI0203(backend, token, id, versionValue, dest)
	case "install":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("установка требует ID@версия")
		}
		id, versionValue, ok := parseRegistryCoordinate0203(args[1])
		if !ok {
			return errors.New("установка требует координату ID@версия")
		}
		scope := strings.TrimSpace(flagValue(args, "--scope", "global"))
		scopeID := strings.TrimSpace(flagValue(args, "--scope-id", ""))
		payload, err := httpJSONWithAuth(http.MethodPost, backend+"/api/v1/admin/extension-registry/extensions/"+url.PathEscape(id)+"/versions/"+url.PathEscape(versionValue)+"/install", map[string]any{"scope": scope, "scopeId": scopeID}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	default:
		return fmt.Errorf("неизвестная реестр расширений-подкоманда: %s", args[0])
	}
}

func parseRegistryCoordinate0203(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	at := strings.LastIndex(value, "@")
	if at <= 0 || at == len(value)-1 {
		return value, "", false
	}
	return value[:at], value[at+1:], true
}

func extensionRegistryPublishCLI0203(backend, token, packagePath string, args []string, out string) error {
	file, err := os.Open(packagePath)
	if err != nil {
		return err
	}
	defer file.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("artifact", filepath.Base(packagePath))
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, file); err != nil {
		return err
	}
	fields := map[string]string{
		"publisher": flagValue(args, "--publisher", ""), "channels": flagValue(args, "--channels", flagValue(args, "--channel", "stable")),
		"minNeverLauncher": flagValue(args, "--min-launcher", ""), "maxNeverLauncher": flagValue(args, "--max-launcher", ""),
		"minApi": flagValue(args, "--min-api", ""), "maxApi": flagValue(args, "--max-api", ""),
		"os": flagValue(args, "--os", ""), "arch": flagValue(args, "--arch", ""),
	}
	for key, value := range fields {
		if strings.TrimSpace(value) != "" {
			if err := writer.WriteField(key, value); err != nil {
				return err
			}
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, backend+"/api/v1/admin/extension-registry/publish", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	payload := map[string]any{}
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			return fmt.Errorf("реестр публикация возвращён недопустимый JSON: %w", err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("реестр публикация возвращён %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return writeOrPrintJSON(out, payload)
}

func extensionRegistryPullCLI0203(backend, token, id, versionValue, dest string) error {
	endpoint := backend + "/api/v1/admin/extension-registry/extensions/" + url.PathEscape(id) + "/versions/" + url.PathEscape(versionValue) + "/artifact"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("реестр pull возвращён %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(dest)), 0o755); err != nil && filepath.Dir(filepath.Clean(dest)) != "." {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(filepath.Clean(dest)), ".registry-pull-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if err != nil {
		return err
	}
	if expected := strings.Trim(resp.Header.Get("ETag"), `"`); expected != "" && !strings.EqualFold(expected, hex.EncodeToString(h.Sum(nil))) {
		return errors.New("загрузка реестр артефакт SHA-256 делает не соответствовать ETag")
	}
	if resp.ContentLength >= 0 && size != resp.ContentLength {
		return errors.New("загрузка реестр артефакт размер несоответствие")
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFileAtomically0202(tmpPath, filepath.Clean(dest), 0o644); err != nil {
		return err
	}
	ok = true
	printJSON(map[string]any{"pulled": true, "extensionId": id, "version": versionValue, "path": dest, "sha256": hex.EncodeToString(h.Sum(nil)), "size": size, "packageIdentity": resp.Header.Get("X-NeverLauncher-Package-Identity")})
	return nil
}
