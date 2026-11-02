package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// checkJavaUI0489 is repeated on both sides of a JVM callback so a concurrent
// permission revocation, disable or package replacement fails closed.
func (s *Supervisor) checkJavaUI0489(ctx context.Context, st *processState, method string, raw json.RawMessage) error {
	var params struct {
		Surface  string `json:"surface"`
		ActionID string `json:"actionId"`
		Key      string `json:"key"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return errors.New("invalid Java UI request")
	}
	if !javaUIContribution0489(st.manifest, params.Surface, method, params.ActionID, params.Key) {
		return errors.New("Java UI contribution not declared in signed package")
	}
	permission := "ui:contribute"
	if params.Surface == "desktop" {
		permission = "desktop:contribute"
	}
	projectID := ""
	if st.key.Scope == "project" {
		projectID = st.key.ScopeID
	}
	allowed, err := s.permissionAllowed0207(ctx, st, permission, projectID)
	if err != nil || !allowed {
		return errors.New("Java UI contribution permission denied")
	}
	if strings.HasPrefix(method, "ui.settings.") {
		permission = "storage:read"
		if method == "ui.settings.put" {
			permission = "storage:write"
		}
		allowed, err = s.permissionAllowed0207(ctx, st, permission, projectID)
		if err != nil || !allowed {
			return errors.New("Java UI settings capability denied")
		}
	}
	return nil
}

func javaUIContribution0489(manifest model.ExtensionManifest, surface, method, actionID, key string) bool {
	var actions []string
	switch surface {
	case "admin":
		if manifest.Admin == nil {
			return false
		}
		for _, a := range manifest.Admin.Actions {
			actions = append(actions, a.ID)
		}
	case "desktop":
		if manifest.Desktop == nil {
			return false
		}
		for _, a := range manifest.Desktop.Actions {
			actions = append(actions, a.ID)
		}
	default:
		return false
	}
	hasBackend := false
	for _, t := range manifest.Targets {
		if t.Kind == "backend" {
			hasBackend = true
			break
		}
	}
	if !hasBackend {
		return false
	}
	switch method {
	case "ui.action.invoke":
		if actionID == "" {
			return false
		}
		for _, allowed := range actions {
			if allowed == actionID {
				return true
			}
		}
		return false
	case "ui.settings.get", "ui.settings.put":
		return len(key) > 0 && len(key) <= 64 && key[0] >= 'a' && key[0] <= 'z' &&
			strings.IndexFunc(key, func(r rune) bool { return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') }) == -1
	default:
		return false
	}
}
