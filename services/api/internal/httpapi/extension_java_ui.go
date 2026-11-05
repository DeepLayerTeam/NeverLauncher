package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Привязка выполняется только к текущей идентичности установки, но не к произвольному ID
// расширения. Обработчики JVM получают аутентифицированного субъекта, а не заданную
// вызывающим идентичность.
func (s Server) invokeJavaUI0489(r *http.Request, install model.ExtensionInstall, method string, raw json.RawMessage, actorID, actorEmail string) (json.RawMessage, error) {
	if s.ExtensionHost == nil {
		return nil, errors.New("Недоступно: Java хост расширений")
	}
	var args struct {
		Version    string          `json:"version"`
		Generation int64           `json:"generation"`
		ActionID   string          `json:"actionId"`
		Key        string          `json:"key"`
		Payload    json.RawMessage `json:"payload"`
		Value      json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, errors.New("Некорректное значение: Java UI параметры")
	}
	if args.Version != install.CurrentVersion || args.Generation != install.Generation || args.Version == "" {
		return nil, errors.New("Установка интерфейса Java устарела")
	}
	surface := "admin"
	if strings.HasPrefix(r.URL.Path, "/api/v1/desktop/") {
		surface = "desktop"
	}
	payload := map[string]any{"surface": surface}
	switch method {
	case "java.action.invoke":
		if args.ActionID == "" || len(args.Payload) == 0 || len(args.Payload) > 24<<10 || args.Payload[0] != '{' || !json.Valid(args.Payload) {
			return nil, errors.New("UI action: требуется «bounded JSON payload»")
		}
		payload["actionId"] = args.ActionID
		payload["payload"] = json.RawMessage(args.Payload)
		payload["actor"] = map[string]string{"id": actorID, "email": actorEmail}
	case "java.settings.get":
		payload["key"] = args.Key
	case "java.settings.put":
		if len(args.Value) == 0 || len(args.Value) > 24<<10 || !json.Valid(args.Value) || string(args.Value) == "null" {
			return nil, errors.New("Некорректное значение: «settings value»")
		}
		payload["key"] = args.Key
		payload["value"] = json.RawMessage(args.Value)
	default:
		return nil, fmt.Errorf("Не поддерживается: «Java UI method» %q", method)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rpcMethod := strings.Replace(method, "java.", "ui.", 1)
	return s.ExtensionHost.CallJavaRPC0304(r.Context(), extensionhost.Key{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID}, rpcMethod, encoded)
}
