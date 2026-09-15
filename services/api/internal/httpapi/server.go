package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

type Server struct {
	Version string
	Config  config.Config
	Repo    repository.Repository
	Storage storage.Storage
	State   *RuntimeState
}

type statusResponse struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	Environment string `json:"environment"`
	Message     string `json:"message"`
	Storage     string `json:"storage"`
}

type contractInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type contractsResponse struct {
	Items []contractInfo `json:"items"`
}

type loginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	TOTP         string `json:"totp,omitempty"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
	DeviceID     string `json:"deviceId,omitempty"`
}

type userWriteRequest struct {
	Email        string            `json:"email"`
	DisplayName  string            `json:"displayName"`
	RoleID       string            `json:"roleId"`
	Password     string            `json:"password"`
	ProjectRoles map[string]string `json:"projectRoles"`
}

type passwordResetRequest struct {
	Password string `json:"password"`
}
type publishRequest struct {
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
}

type createVersionRequest struct {
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
}

type telemetryRequest struct {
	ProjectID       string `json:"projectId"`
	ProfileID       string `json:"profileId"`
	LauncherVersion string `json:"launcherVersion"`
	ProfileVersion  string `json:"profileVersion"`
	Event           string `json:"event"`
	Status          string `json:"status"`
}

type crashRequest struct {
	ProjectID       string `json:"projectId"`
	ProfileID       string `json:"profileId"`
	LauncherVersion string `json:"launcherVersion"`
	ProfileVersion  string `json:"profileVersion"`
	Message         string `json:"message"`
	Log             string `json:"log"`
}

func (s Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Name: "NeverLauncher API", Version: s.Version, Status: "ok", Environment: s.Config.Environment, Message: "Backend API работает", Storage: s.Storage.Driver()})
}

func (s Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Name: "NeverLauncher", Version: s.Version, Status: "ok", Environment: s.Config.Environment, Message: "Сервис доступен", Storage: s.Storage.Driver()})
}

func (s Server) contracts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, contractsResponse{Items: []contractInfo{{Name: "Backend API", Path: "schemas/openapi.yaml", Type: "openapi"}}})
}

func (s Server) compatibility(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "status": "canonical-v1", "contracts": []string{"schemas/openapi.yaml"}, "policy": []string{"historical /api/v2-/api/v5 routes are removed", "database migrations are checksum-enforced", "signed manifests are required"}})
}

func (s Server) adminCompatibility(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version,
		"status":  "plugin_first_platform_ready",
		"checks": []map[string]any{
			{"name": "manifest_schema", "status": "frozen_for_2x"},
			{"name": "openapi", "status": "frozen_for_2x"},
			{"name": "migrations", "status": "sequential"},
			{"name": "release_notes_policy", "status": "changelog_and_gitflic_release_only"},
		},
	})
}

func (s Server) runtimeRequirements(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version,
		"java": map[string]any{
			"supportedMajorVersions":  []int{8, 17, 21, 25},
			"recommendedMajorVersion": 21,
			"allowCustomPath":         true,
			"managedDistribution":     "temurin",
			"managedInstall":          true,
		},
		"memory": map[string]any{
			"minimumMb":     1024,
			"recommendedMb": 4096,
			"maximumMb":     8192,
		},
		"launch": map[string]any{
			"classpathStrategy": "compatibility",
			"nativesDirectory":  "natives",
			"offlineMode":       true,
		},
	})
}

func (s Server) launchTemplate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          "recommended",
		"name":        "Recommended",
		"description": "Шаблон профиля запуска Minecraft для NeverLauncher",
		"minecraft": map[string]any{
			"version": "1.21.1",
			"loader":  "vanilla",
		},
		"runtime": map[string]any{
			"java":    map[string]any{"majorVersion": 21, "distribution": "temurin", "allowCustomPath": true},
			"jvmArgs": []string{"-Xms2G", "-Xmx4G"},
			"memory":  map[string]any{"minimumMb": 1024, "recommendedMb": 4096, "maximumMb": 8192},
			"launch":  map[string]any{"classpathStrategy": "compatibility", "nativesDirectory": "natives", "offlineMode": true},
		},
	})
}

func (s Server) loaders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "items": loaderCatalog()})
}

func (s Server) loader(w http.ResponseWriter, r *http.Request) {
	loaderID := strings.ToLower(r.PathValue("loaderId"))
	for _, item := range loaderCatalog() {
		if strings.EqualFold(item["id"].(string), loaderID) {
			writeJSON(w, http.StatusOK, item)
			return
		}
	}
	writeError(w, http.StatusNotFound, "загрузчик не найден")
}

func (s Server) loaderCompatibility(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version,
		"engine": map[string]any{
			"status":                 "production",
			"classpathStrategy":      "compatibility",
			"signedMetadataRequired": true,
			"inheritance":            true,
			"mojangRules":            true,
			"orderedClasspath":       true,
		},
		"loaders": loaderCatalog(),
	})
}

func loaderCatalog() []map[string]any {
	return []map[string]any{
		{"id": "vanilla", "name": "Vanilla", "resolution": "mojang-version-manifest-v2", "adapter": "compatibility-engine", "installer": "neverlauncher-vanilla-materializer", "managedJava": true},
		{"id": "fabric", "name": "Fabric", "resolution": "inherited-version-json", "adapter": "planned", "installer": "planned"},
		{"id": "quilt", "name": "Quilt", "resolution": "inherited-version-json", "adapter": "planned", "installer": "planned"},
		{"id": "forge", "name": "Forge", "resolution": "inherited-version-json", "adapter": "planned", "installer": "planned"},
		{"id": "neoforge", "name": "NeoForge", "resolution": "inherited-version-json", "adapter": "planned", "installer": "planned"},
	}
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("не удалось записать JSON-ответ: %v", err)
	}
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/health") && !strings.HasPrefix(r.URL.Path, "/ready") && !strings.HasPrefix(r.URL.Path, "/metrics") {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if _, ok := allowed[origin]; !ok {
				if r.Method == http.MethodOptions {
					writeError(w, http.StatusForbidden, "CORS origin не разрешён")
					return
				}
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
		}
		if r.Method == http.MethodOptions {
			if origin == "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if _, ok := allowed[origin]; ok {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
