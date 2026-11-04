package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionbroker"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Проверяйте соответствие оператора до любого утверждения об исполнении с
// изоляцией ОС.
func (s *Supervisor) validateSharedRoots03110(policy *model.ExtensionSandboxPolicy) error {
	if policy == nil || policy.Mode != "isolated" {
		return nil
	}
	if s.sharedRootsErr != nil {
		return fmt.Errorf("sandbox broker configuration invalid: %w", s.sharedRootsErr)
	}
	for _, grant := range append(append([]string{}, policy.FilesystemRead...), policy.FilesystemWrite...) {
		if !strings.HasPrefix(grant, "shared:") {
			continue
		}
		name := strings.TrimPrefix(grant, "shared:")
		if s.sharedRoots[name] == "" {
			return fmt.Errorf("sandbox broker shared root %q not configured", name)
		}
		// Повторно проверяйте при запуске и каждой операции: если корень заменён
		// символьной ссылкой, доступ к другому поддереву не появляется незаметно.
		raw, err := json.Marshal(map[string]string{name: s.sharedRoots[name]})
		if err != nil {
			return err
		}
		if _, err := extensionbroker.ParseRoots(string(raw)); err != nil {
			return fmt.Errorf("sandbox broker shared root %q unavailable: %w", name, err)
		}
	}
	return nil
}

func (s *Supervisor) fileCapability03110(ctx context.Context, st *processState, operation string, req capabilityRequest) capabilityResult0205 {
	policy := st.manifest.Sandbox
	if policy == nil || policy.Mode != "isolated" || !sandboxEnforced03110(st) {
		return capabilityResult0205{status: http.StatusForbidden, err: errors.New("scoped filesystem broker requires running OS-isolated package")}
	}
	grant := "shared:" + req.Name
	permission := "storage:read"
	grants := policy.FilesystemRead
	if operation == "fs.write" {
		permission = "storage:write"
		grants = policy.FilesystemWrite
	}
	if !extensionbroker.HasGrant(grants, grant) {
		return capabilityResult0205{status: http.StatusForbidden, err: errors.New("filesystem resource outside signed policy")}
	}
	allowed, err := s.permissionAllowed0207(ctx, st, permission, st.key.ScopeID)
	if err != nil {
		return capabilityResult0205{status: http.StatusServiceUnavailable, err: errors.New("filesystem capability authorization unavailable")}
	}
	if !allowed {
		return capabilityResult0205{status: http.StatusForbidden, err: errors.New("filesystem capability permission denied")}
	}
	if err := s.validateSharedRoots03110(policy); err != nil {
		return capabilityResult0205{status: http.StatusServiceUnavailable, err: err}
	}
	root := s.sharedRoots[req.Name]
	if root == "" {
		return capabilityResult0205{status: http.StatusForbidden, err: errors.New("filesystem resource not mapped")}
	}
	if operation == "fs.read" {
		data, err := extensionbroker.Read(root, req.Path)
		if err != nil {
			return capabilityResult0205{status: http.StatusForbidden, err: errors.New("scoped filesystem read denied")}
		}
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"contentBase64": data}}
	}
	if err := extensionbroker.Write(root, req.Path, req.BodyBase64); err != nil {
		return capabilityResult0205{status: http.StatusForbidden, err: errors.New("scoped filesystem write denied")}
	}
	return capabilityResult0205{status: http.StatusOK, value: map[string]any{"written": true}}
}

// Хост переводит sandboxReady при обслуживании HTTP-запросов возможностей.
// Готовность нужно считать неизменной в пределах запроса и синхронизировать с
// жизненным циклом.
func sandboxEnforced03110(st *processState) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sandboxReady
}
