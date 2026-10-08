package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type runtimeEvidenceCLI0212 struct {
	SchemaVersion    string            `json:"schemaVersion"`
	PackageID        string            `json:"packageId"`
	ManifestDigest   string            `json:"manifestDigest"`
	TargetID         string            `json:"targetId"`
	MinecraftVersion string            `json:"minecraftVersion"`
	Loader           string            `json:"loader"`
	OS               string            `json:"os"`
	Arch             string            `json:"arch"`
	Java             string            `json:"java"`
	ActualClient     bool              `json:"actualClient"`
	ExitCode         int               `json:"exitCode"`
	ServerJoin       bool              `json:"serverJoin"`
	RunID            string            `json:"runId"`
	Commit           string            `json:"commit"`
	EvidenceHashes   map[string]string `json:"evidenceHashes"`
	StartedAt        time.Time         `json:"startedAt"`
	FinishedAt       time.Time         `json:"finishedAt"`
}

type runtimeSignedCLI0212 struct {
	KeyID     string                 `json:"keyId"`
	Evidence  runtimeEvidenceCLI0212 `json:"evidence"`
	Signature string                 `json:"signature"`
}

func loadRuntimePrivateKey0212(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(raw))
	var decoded []byte
	if b, e := hex.DecodeString(value); e == nil {
		decoded = b
	} else {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			if b, e := enc.DecodeString(value); e == nil {
				decoded = b
				break
			}
		}
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(decoded), nil
	}
	return nil, errors.New("среда выполнения ключ подписи должен contain Ed25519 seed/private ключ как hex/base64")
}

func handlePipeline(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные pipeline-подкоманды: plan, каналы, состояние, подготавливать, целостность-проверка, быстрая проверка, валидация, среда выполнения-подпись, среда выполнения-отправить, политика-получить, политика-задать, публикация, откат, аудит")
	}
	out := flagValue(args, "--output", "")
	project := flagValue(args, "--project", "")
	profile := flagValue(args, "--profile", "vanilla")
	channel := flagValue(args, "--channel", "stable")
	ver := flagValue(args, "--version", version)
	packageID := flagValue(args, "--package-id", "")
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)

	if args[0] == "plan" {
		if backend == "" {
			return errors.New("конвейер plan требует --серверная часть: план строится только относительно реального Серверная часть API")
		}
		payload := map[string]any{
			"schemaVersion": cliSchemaVersion,
			"toolVersion":   version,
			"backend":       backend,
			"projectId":     project,
			"profileId":     profile,
			"channel":       channel,
			"version":       ver,
			"packageId":     packageID,
			"operations": []string{
				"POST /api/v1/packages/{packageId}/validate",
				"POST /api/v1/packages/{packageId}/sign",
				"POST /api/v1/packages/{packageId}/stage",
				"POST /api/v1/packages/{packageId}/integrity-check",
				"POST /api/v1/packages/{packageId}/runtime-validations/evidence",
				"GET /api/v1/packages/{packageId}/validations",
				"POST /api/v1/packages/{packageId}/publish",
				"POST /api/v1/channels/{channel}/rollback",
			},
		}
		return writeOrPrintJSON(out, payload)
	}
	if backend == "" && args[0] != "runtime-sign" {
		return errors.New("конвейер операция требует --серверная часть")
	}
	if token == "" && args[0] != "channels" && args[0] != "runtime-sign" {
		return errors.New("конвейер операция требует --токен или NEVERLAUNCHER_TOKEN")
	}

	switch args[0] {
	case "channels":
		if project == "" {
			return errors.New("конвейер каналы требует --проект")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/projects/"+url.PathEscape(project)+"/channels", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "status":
		if packageID == "" {
			return errors.New("конвейер состояние требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/packages/"+url.PathEscape(packageID), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "stage":
		if packageID == "" {
			return errors.New("конвейер подготавливать требует --пакет-ID")
		}
		validate, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/validate", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("пакет валидация ошибка: %w", err)
		}
		sign, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/sign", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("пакет подписание ошибка: %w", err)
		}
		staged, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/stage", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("пакет подготавливать ошибка: %w", err)
		}
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "validate": validate, "sign": sign, "stage": staged})
	case "integrity-check":
		if packageID == "" {
			return errors.New("конвейер целостность-проверка требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/integrity-check", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "smoke-test":
		if packageID == "" {
			return errors.New("конвейер быстрая проверка требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/smoke-test", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, map[string]any{"legacyCommand": "smoke-test", "validationKind": "integrity", "runtimeExecuted": false, "warning": "legacy smoke-test performs integrity validation only; no Minecraft runtime was executed", "response": payload})
	case "validations":
		if packageID == "" {
			return errors.New("конвейер валидация требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/validations", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "runtime-sign":
		inputPath := flagValue(args, "--input", "")
		keyPath := flagValue(args, "--private-key", "")
		keyID := flagValue(args, "--key-id", "")
		if inputPath == "" || keyPath == "" || keyID == "" {
			return errors.New("конвейер среда выполнения-подпись требует --input <свидетельство.JSON> --закрытый-ключ <файл> --ключ-ID <ID>")
		}
		raw, err := os.ReadFile(inputPath)
		if err != nil {
			return err
		}
		var evidence runtimeEvidenceCLI0212
		if err := json.Unmarshal(raw, &evidence); err != nil {
			return fmt.Errorf("свидетельство реального запуска JSON: %w", err)
		}
		if evidence.SchemaVersion != "neverlauncher/runtime-validation/v1" || evidence.PackageID == "" || evidence.ManifestDigest == "" || evidence.TargetID == "" {
			return errors.New("свидетельство реального запуска отсутствующий канонический schema/package/manifest/target")
		}
		privateKey, err := loadRuntimePrivateKey0212(keyPath)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		signed := runtimeSignedCLI0212{KeyID: keyID, Evidence: evidence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
		return writeOrPrintJSON(out, signed)
	case "runtime-submit":
		if packageID == "" {
			return errors.New("конвейер среда выполнения-отправить требует --пакет-ID")
		}
		evidencePath := flagValue(args, "--evidence", "")
		if evidencePath == "" {
			return errors.New("конвейер среда выполнения-отправить требует --свидетельство <подписанный-JSON>")
		}
		raw, err := os.ReadFile(evidencePath)
		if err != nil {
			return err
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("свидетельство реального запуска JSON: %w", err)
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/runtime-validations/evidence", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "policy-get":
		if project == "" {
			return errors.New("конвейер политика-получить требует --проект")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/projects/"+url.PathEscape(project)+"/validation-policy", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "policy-set":
		if project == "" {
			return errors.New("конвейер политика-задать требует --проект")
		}
		level := strings.ToLower(flagValue(args, "--level", "integrity"))
		if level != "integrity" && level != "runtime" {
			return errors.New("--уровень должен быть целостность или среда выполнения")
		}
		body := map[string]any{"requiredLevel": level, "requireServerJoin": flagValue(args, "--require-server-join", "false") == "true"}
		payload, err := httpJSONWithAuth("PUT", backend+"/api/v1/projects/"+url.PathEscape(project)+"/validation-policy", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "publish":
		if packageID == "" {
			return errors.New("конвейер публикация требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/publish", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "rollback":
		if project == "" {
			return errors.New("конвейер откат требует --проект")
		}
		toVersion := flagValue(args, "--to", "")
		if toVersion == "" || toVersion == "previous" {
			return errors.New("конвейер откат требует явный --к <версия>; неявный предыдущий запрещён")
		}
		body := map[string]any{"projectId": project, "profileId": profile, "toVersion": toVersion}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/channels/"+url.PathEscape(channel)+"/rollback", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "audit":
		if packageID == "" {
			return errors.New("конвейер аудит требует --пакет-ID")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/admin/audit", nil, token)
		if err != nil {
			return err
		}
		items, _ := payload["items"].([]any)
		filtered := make([]any, 0)
		for _, raw := range items {
			item, _ := raw.(map[string]any)
			target, _ := item["target"].(string)
			if strings.Contains(target, packageID) || target == packageID {
				filtered = append(filtered, item)
			}
		}
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "packageId": packageID, "events": filtered, "count": len(filtered)})
	default:
		return fmt.Errorf("неизвестная pipeline-подкоманда: %s", args[0])
	}
}

func handleClient(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные client-подкоманды: установка, обновление, проверять, repair, очистка, откат, пакет-сборка, пакет-проверять, загрузка-plan, пакет-загрузка, публикация-канал, пакет-публикация, пакет-релиз, пакет-состояние, канал-состояние, использовать-plan, пакет-использовать, пакет-применить, локальный-состояние, откат-снимок, пакет-конвейер, пакет-подготавливать, package-быстрая проверка, пакет-продвигать")
	}
	profile := flagValue(args, "--profile", "vanilla")
	channel := flagValue(args, "--channel", "stable")
	clientDir := flagValue(args, "--client-dir", ".neverlauncher/client")
	manifestPath := flagValue(args, "--manifest", "manifest.json")
	out := flagValue(args, "--output", "")
	var payload map[string]any
	switch args[0] {
	case "install", "update":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := clientInstallOrUpdate(pkgPath, flagValue(args, "--storage-dir", ".neverlauncher/storage"), clientDir, args[0])
		if err != nil {
			return err
		}
		payload = report
	case "verify":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := verifyClientInstallation(pkgPath, clientDir)
		if err != nil {
			return err
		}
		payload = map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": map[bool]string{true: "valid", false: "invalid"}[report.Valid], "verify": report}
		if !report.Valid {
			return fmt.Errorf("клиент проверять ошибка: отсутствующий=%v повреждённый=%v", report.Missing, report.Corrupted)
		}
	case "repair":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := repairClientInstallation(pkgPath, flagValue(args, "--storage-dir", ".neverlauncher/storage"), clientDir, flagValue(args, "--repair-optional", "false") == "true")
		if err != nil {
			return err
		}
		payload = report
	case "cleanup":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := cleanupClientInstallation(pkgPath, clientDir)
		if err != nil {
			return err
		}
		payload = report
	case "rollback":
		report, err := rollbackClientInstallation(clientDir, flagValue(args, "--target", "previous"))
		if err != nil {
			return err
		}
		payload = report
	case "package-build":
		pkg, err := buildClientPackage(clientDir, flagValue(args, "--project", "demo-project"), profile, channel, flagValue(args, "--version", version), flagValue(args, "--base-url", ""))
		if err != nil {
			return err
		}
		payload = pkg
	case "package-verify":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := verifyClientPackage(pkgPath)
		if err != nil {
			return err
		}
		payload = report
	case "upload-plan":
		pkgPath := flagValue(args, "--package", manifestPath)
		plan, err := clientUploadPlan(pkgPath, flagValue(args, "--storage", "s3-compatible"), flagValue(args, "--prefix", "clients/"+profile+"/"+channel))
		if err != nil {
			return err
		}
		payload = plan
	case "package-upload":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := clientPackageUpload(pkgPath, flagValue(args, "--client-dir", clientDir), flagValue(args, "--storage-dir", ".neverlauncher/storage"), flagValue(args, "--prefix", "clients/"+profile+"/"+channel))
		if err != nil {
			return err
		}
		payload = report
	case "publish-channel":
		pkgPath := flagValue(args, "--package", manifestPath)
		plan, err := clientPublishChannelPlan(pkgPath, channel)
		if err != nil {
			return err
		}
		payload = plan
	case "package-publish":
		pkgPath := flagValue(args, "--package", manifestPath)
		report, err := clientPackagePublish(pkgPath, channel, flagValue(args, "--registry-dir", ".neverlauncher/publications"), flagValue(args, "--upload-report", ""))
		if err != nil {
			return err
		}
		payload = report
	case "package-release":
		report, err := clientPackageRelease(clientDir, flagValue(args, "--project", "demo-project"), profile, channel, flagValue(args, "--version", version), flagValue(args, "--base-url", ""), flagValue(args, "--storage-dir", ".neverlauncher/storage"), flagValue(args, "--registry-dir", ".neverlauncher/publications"), flagValue(args, "--dist-dir", ".neverlauncher/dist"))
		if err != nil {
			return err
		}
		payload = report
	case "package-status":
		report, err := clientPackageStatus(flagValue(args, "--registry-dir", ".neverlauncher/publications"), flagValue(args, "--project", "demo-project"), profile, channel, flagValue(args, "--version", ""))
		if err != nil {
			return err
		}
		payload = report
	case "channel-status":
		report, err := clientPackageStatus(flagValue(args, "--registry-dir", ".neverlauncher/publications"), flagValue(args, "--project", "demo-project"), profile, channel, flagValue(args, "--version", ""))
		if err != nil {
			return err
		}
		report["kind"] = "channel-status"
		report["desktopConsumption"] = "ready"
		payload = report
	case "consume-plan":
		plan, err := clientConsumePlan(flagValue(args, "--package", manifestPath), clientDir)
		if err != nil {
			return err
		}
		payload = plan
	case "package-consume", "package-apply":
		report, err := clientPackageConsume(flagValue(args, "--package", manifestPath), flagValue(args, "--storage-dir", ".neverlauncher/storage"), clientDir)
		if err != nil {
			return err
		}
		payload = report
	case "local-state":
		state, err := clientLocalState(clientDir, profile, channel)
		if err != nil {
			return err
		}
		payload = state
	case "package-pipeline":
		return handlePipeline(append([]string{"plan"}, args[1:]...))
	case "package-stage":
		return handlePipeline(append([]string{"stage"}, args[1:]...))
	case "package-smoke-test":
		return handlePipeline(append([]string{"smoke-test"}, args[1:]...))
	case "package-integrity-check":
		return handlePipeline(append([]string{"integrity-check"}, args[1:]...))
	case "package-promote":
		return handlePipeline(append([]string{"publish"}, args[1:]...))
	case "rollback-snapshot":
		pkgPath := flagValue(args, "--package", manifestPath)
		snapshot, err := clientRollbackSnapshot(pkgPath, flagValue(args, "--from", "current"), flagValue(args, "--to", "previous"))
		if err != nil {
			return err
		}
		payload = snapshot
	default:
		return fmt.Errorf("неизвестная client-подкоманда: %s", args[0])
	}
	if out != "" && out != "-" {
		return writeJSONFile(out, payload)
	}
	printJSON(payload)
	return nil
}

type ClientPackageFile struct {
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	URL        string   `json:"url,omitempty"`
	Required   bool     `json:"required"`
	Group      string   `json:"group"`
	TargetOS   []string `json:"targetOs,omitempty"`
	Executable bool     `json:"executable,omitempty"`
}

type ClientPackageManifest struct {
	SchemaVersion string              `json:"schemaVersion"`
	ToolVersion   string              `json:"toolVersion"`
	ProjectID     string              `json:"projectId"`
	ProfileID     string              `json:"profileId"`
	Channel       string              `json:"channel"`
	Version       string              `json:"version"`
	CreatedAt     string              `json:"createdAt"`
	PackageID     string              `json:"packageId"`
	Files         []ClientPackageFile `json:"files"`
	FileGroups    []map[string]any    `json:"fileGroups"`
	DeleteRules   []map[string]any    `json:"deleteRules"`
	Rollback      map[string]any      `json:"rollback"`
	Summary       map[string]any      `json:"summary"`
}

func buildClientPackage(clientDir, project, profile, channel, ver, baseURL string) (map[string]any, error) {
	files := []ClientPackageFile{}
	var total int64
	err := filepath.WalkDir(clientDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("клиент пакет запрещает символическая ссылка: %s", path)
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".git") || name == "node_modules" || name == ".neverlauncher-cache" || name == ".neverlauncher" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(clientDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") || rel == "." {
			return fmt.Errorf("небезопасный путь клиент пакет: %s", rel)
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		group, required := classifyClientFile(rel)
		url := ""
		if baseURL != "" {
			url = strings.TrimRight(baseURL, "/") + "/" + rel
		}
		files = append(files, ClientPackageFile{Path: rel, Size: size, SHA256: sum, URL: url, Required: required, Group: group, Executable: isExecutablePath(rel)})
		total += size
		return nil
	})
	if err != nil {
		return nil, err
	}
	manifest := ClientPackageManifest{
		SchemaVersion: cliSchemaVersion,
		ToolVersion:   version,
		ProjectID:     project,
		ProfileID:     profile,
		Channel:       channel,
		Version:       ver,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		PackageID:     project + ":" + profile + ":" + channel + ":" + ver,
		Files:         files,
		FileGroups: []map[string]any{
			{"id": "runtime", "required": true, "paths": []string{"versions/**", "natives/**"}},
			{"id": "libraries", "required": true, "paths": []string{"libraries/**"}},
			{"id": "assets", "required": true, "paths": []string{"assets/**", "resources/**"}},
			{"id": "mods", "required": true, "paths": []string{"mods/*.jar"}},
			{"id": "optional-mods", "required": false, "paths": []string{"mods/optional/**", "optional/**"}},
			{"id": "config", "required": true, "paths": []string{"config/**"}},
		},
		DeleteRules: []map[string]any{
			{"id": "known-orphans", "action": "quarantine", "paths": []string{"mods/*.jar", "libraries/**", "versions/**"}},
			{"id": "user-data", "action": "keep", "paths": []string{"saves/**", "screenshots/**", "options.txt", "resourcepacks/**"}},
		},
		Rollback: map[string]any{"snapshot": "rollback-" + profile + "-" + channel + "-" + ver + ".json", "strategy": "manifest-and-file-state", "keepUserData": true},
		Summary:  map[string]any{"files": len(files), "totalSize": total, "required": countRequired(files, true), "optional": countRequired(files, false)},
	}
	b, _ := json.Marshal(manifest)
	packageHash := sha256.Sum256(b)
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "kind": "client-package", "manifestSha256": hex.EncodeToString(packageHash[:]), "manifest": manifest}, nil
}

func verifyClientPackage(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	manifest := raw
	if nested, ok := raw["manifest"].(map[string]any); ok {
		manifest = nested
	}
	errs := []string{}
	warnings := []string{}
	for _, field := range []string{"schemaVersion", "projectId", "profileId", "channel", "version", "files"} {
		if _, ok := manifest[field]; !ok {
			errs = append(errs, "отсутствует поле "+field)
		}
	}
	if files, ok := manifest["files"].([]any); ok {
		seen := map[string]bool{}
		for _, item := range files {
			f, ok := item.(map[string]any)
			if !ok {
				errs = append(errs, "files содержит некорректный элемент")
				continue
			}
			path := fmt.Sprint(f["path"])
			sha := fmt.Sprint(f["sha256"])
			if path == "" || path == "<nil>" {
				errs = append(errs, "файл без path")
			}
			if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
				errs = append(errs, "небезопасный path: "+path)
			}
			if seen[path] {
				errs = append(errs, "дублирующийся path: "+path)
			}
			seen[path] = true
			if len(sha) != 64 {
				errs = append(errs, "sha256 должен быть hex-строкой длиной 64 для "+path)
			}
		}
	} else {
		errs = append(errs, "files должен быть массивом")
	}
	if _, ok := manifest["rollback"]; !ok {
		warnings = append(warnings, "rollback snapshot policy не задан")
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "package": path, "valid": len(errs) == 0, "errors": errs, "warnings": warnings, "checks": []string{"schema", "safe-paths", "unique-paths", "sha256", "rollback-policy"}}, nil
}

func clientUploadPlan(packagePath, storage, prefix string) (map[string]any, error) {
	report, err := verifyClientPackage(packagePath)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "package": packagePath, "storage": storage, "prefix": strings.Trim(prefix, "/"), "stages": []string{"verify-package", "upload-required-files", "upload-optional-files", "upload-manifest", "verify-remote-checksums", "write-publication-record"}, "verification": report, "status": "planned"}, nil
}

func clientPublishChannelPlan(packagePath, channel string) (map[string]any, error) {
	report, err := verifyClientPackage(packagePath)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "package": packagePath, "channel": channel, "transaction": []string{"lock-channel", "verify-package", "create-release-version", "attach-manifest", "promote-channel-pointer", "write-audit-event", "unlock-channel"}, "rollback": "restore-previous-channel-pointer", "verification": report, "status": "planned"}, nil
}

func clientRollbackSnapshot(packagePath, from, to string) (map[string]any, error) {
	report, err := verifyClientPackage(packagePath)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "package": packagePath, "from": from, "to": to, "snapshot": map[string]any{"manifest": packagePath, "fileState": "client-state-" + from + ".json", "keepUserData": true, "restoreChannelPointer": true}, "verification": report, "status": "ready"}, nil
}

func readClientPackageManifest(path string) (ClientPackageManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ClientPackageManifest{}, err
	}
	var wrapper struct {
		Manifest ClientPackageManifest `json:"manifest"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Manifest.PackageID != "" {
		return wrapper.Manifest, nil
	}
	var manifest ClientPackageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ClientPackageManifest{}, err
	}
	if manifest.PackageID == "" {
		return ClientPackageManifest{}, errors.New("клиент пакет манифест не содержит packageId")
	}
	return manifest, nil
}

func clientPackageUpload(packagePath, clientDir, storageDir, prefix string) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		prefix = filepath.ToSlash(filepath.Join("clients", manifest.ProjectID, manifest.ProfileID, manifest.Channel, manifest.Version))
	}
	uploaded := []map[string]any{}
	var uploadedBytes int64
	for _, file := range manifest.Files {
		if err := validateClientPackagePath(file.Path); err != nil {
			return nil, err
		}
		src := filepath.Join(clientDir, filepath.FromSlash(file.Path))
		sum, size, err := hashFile(src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		if sum != file.SHA256 || size != file.Size {
			return nil, fmt.Errorf("%s: checksum/size несоответствие до загрузка", file.Path)
		}
		dst := filepath.Join(storageDir, filepath.FromSlash(prefix), filepath.FromSlash(file.Path))
		if err := copyFileAtomic(src, dst); err != nil {
			return nil, err
		}
		remoteSum, remoteSize, err := hashFile(dst)
		if err != nil {
			return nil, err
		}
		if remoteSum != file.SHA256 || remoteSize != file.Size {
			return nil, fmt.Errorf("%s: удалённый checksum/size несоответствие", file.Path)
		}
		uploadedBytes += size
		uploaded = append(uploaded, map[string]any{"path": file.Path, "sha256": file.SHA256, "size": size, "objectKey": filepath.ToSlash(filepath.Join(prefix, file.Path)), "status": "uploaded"})
	}
	manifestObject := filepath.Join(storageDir, filepath.FromSlash(prefix), "client-package.json")
	if err := writeJSONFile(manifestObject, manifest); err != nil {
		return nil, err
	}
	manifestSHA, manifestSize, err := hashFile(manifestObject)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "packageId": manifest.PackageID, "projectId": manifest.ProjectID, "profileId": manifest.ProfileID, "channel": manifest.Channel, "version": manifest.Version, "storage": map[string]any{"driver": "local", "root": storageDir, "prefix": prefix, "manifestObject": filepath.ToSlash(filepath.Join(prefix, "client-package.json"))}, "uploadedFiles": uploaded, "uploadedBytes": uploadedBytes, "manifest": map[string]any{"sha256": manifestSHA, "size": manifestSize}, "status": "uploaded"}, nil
}

func clientPackagePublish(packagePath, channel, registryDir, uploadReportPath string) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	if channel == "" {
		channel = manifest.Channel
	}
	if channel != manifest.Channel {
		return nil, fmt.Errorf("канал несоответствие: пакет=%s запрошенный=%s", manifest.Channel, channel)
	}
	publication := map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "packageId": manifest.PackageID, "projectId": manifest.ProjectID, "profileId": manifest.ProfileID, "channel": channel, "version": manifest.Version, "publishedAt": time.Now().UTC().Format(time.RFC3339), "manifest": packagePath, "status": "published", "auditEvent": map[string]any{"type": "client-package.published", "actor": "nl", "packageId": manifest.PackageID}}
	if uploadReportPath != "" {
		if data, err := os.ReadFile(uploadReportPath); err == nil {
			var upload map[string]any
			if json.Unmarshal(data, &upload) == nil {
				publication["upload"] = upload
			}
		}
	}
	name := safeArtifactName(manifest.ProjectID + "-" + manifest.ProfileID + "-" + channel + "-" + manifest.Version + ".publication.json")
	path := filepath.Join(registryDir, name)
	if err := writeJSONFile(path, publication); err != nil {
		return nil, err
	}
	publication["publicationRecord"] = path
	return publication, nil
}

func clientPackageRelease(clientDir, project, profile, channel, ver, baseURL, storageDir, registryDir, distDir string) (map[string]any, error) {
	pkg, err := buildClientPackage(clientDir, project, profile, channel, ver, baseURL)
	if err != nil {
		return nil, err
	}
	packagePath := filepath.Join(distDir, project, profile, channel, ver, "client-package.json")
	if err := writeJSONFile(packagePath, pkg); err != nil {
		return nil, err
	}
	upload, err := clientPackageUpload(packagePath, clientDir, storageDir, filepath.ToSlash(filepath.Join("clients", project, profile, channel, ver)))
	if err != nil {
		return nil, err
	}
	uploadPath := filepath.Join(distDir, project, profile, channel, ver, "upload-report.json")
	if err := writeJSONFile(uploadPath, upload); err != nil {
		return nil, err
	}
	publication, err := clientPackagePublish(packagePath, channel, registryDir, uploadPath)
	if err != nil {
		return nil, err
	}
	status, err := clientPackageStatus(registryDir, project, profile, channel, ver)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "pipeline": []string{"package-build", "package-upload", "package-publish", "package-status"}, "packageManifest": packagePath, "uploadReport": uploadPath, "publication": publication, "status": status, "result": "released"}, nil
}

func clientPackageStatus(registryDir, project, profile, channel, ver string) (map[string]any, error) {
	records := []map[string]any{}
	if _, err := os.Stat(registryDir); errors.Is(err, os.ErrNotExist) {
		return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "registryDir": registryDir, "records": records, "status": "empty"}, nil
	}
	err := filepath.WalkDir(registryDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".publication.json") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var rec map[string]any
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
		if project != "" && project != fmt.Sprint(rec["projectId"]) {
			return nil
		}
		if profile != "" && profile != fmt.Sprint(rec["profileId"]) {
			return nil
		}
		if channel != "" && channel != fmt.Sprint(rec["channel"]) {
			return nil
		}
		if ver != "" && ver != fmt.Sprint(rec["version"]) {
			return nil
		}
		rec["recordPath"] = path
		records = append(records, rec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	status := "ready"
	if len(records) == 0 {
		status = "not-found"
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "registryDir": registryDir, "records": records, "status": status}, nil
}

func clientConsumePlan(packagePath, clientDir string) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	missing := []map[string]any{}
	current := []map[string]any{}
	corrupted := []map[string]any{}
	var downloadBytes int64
	for _, file := range manifest.Files {
		if err := validateClientPackagePath(file.Path); err != nil {
			return nil, err
		}
		localPath := filepath.Join(clientDir, filepath.FromSlash(file.Path))
		sum, size, err := hashFile(localPath)
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, map[string]any{"path": file.Path, "size": file.Size, "sha256": file.SHA256, "required": file.Required, "group": file.Group})
			downloadBytes += file.Size
			continue
		}
		if err != nil {
			corrupted = append(corrupted, map[string]any{"path": file.Path, "message": err.Error()})
			downloadBytes += file.Size
			continue
		}
		if sum != file.SHA256 || size != file.Size {
			corrupted = append(corrupted, map[string]any{"path": file.Path, "localSha256": sum, "expectedSha256": file.SHA256, "localSize": size, "expectedSize": file.Size})
			downloadBytes += file.Size
			continue
		}
		current = append(current, map[string]any{"path": file.Path, "sha256": file.SHA256, "size": file.Size, "status": "current"})
	}
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"packageId":     manifest.PackageID,
		"projectId":     manifest.ProjectID,
		"profileId":     manifest.ProfileID,
		"channel":       manifest.Channel,
		"version":       manifest.Version,
		"clientDir":     clientDir,
		"missing":       missing,
		"corrupted":     corrupted,
		"current":       current,
		"downloadBytes": downloadBytes,
		"actions":       []string{"download-missing", "replace-corrupted", "write-client-state", "keep-user-data", "quarantine-orphans"},
		"status":        map[bool]string{true: "ready", false: "update-required"}[len(missing) == 0 && len(corrupted) == 0],
	}, nil
}

func clientPackageConsume(packagePath, storageDir, clientDir string) (map[string]any, error) {
	snapshotID, err := createClientSnapshot(clientDir)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать транзакционный откат снимок: %w", err)
	}
	return clientPackageConsumeTransactional0156(packagePath, storageDir, clientDir, snapshotID)
}

func clientPackageConsumeTransactional0156(packagePath, storageDir, clientDir, snapshotID string) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	prefix := inferStoragePrefix(packagePath, storageDir, manifest)
	files := make([]updaterFileSpec0156, 0, len(manifest.Files)+1)
	applied := make([]map[string]any, 0, len(manifest.Files))
	wanted := make(map[string]bool, len(manifest.Files))
	var appliedBytes int64
	for _, file := range manifest.Files {
		if err := validateClientPackagePath(file.Path); err != nil {
			return nil, err
		}
		rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Path)))
		src := clientPackageSourcePath(packagePath, storageDir, manifest, file)
		files = append(files, updaterFileSpec0156{Path: rel, Source: src, Size: file.Size, SHA256: file.SHA256, Executable: file.Executable})
		wanted[rel] = true
		appliedBytes += file.Size
		applied = append(applied, map[string]any{"path": rel, "sha256": file.SHA256, "size": file.Size, "status": "applied"})
	}
	remove := []string{}
	for _, rel := range currentStatePaths(clientDir) {
		if wanted[rel] || !isManagedClientPath(rel) {
			continue
		}
		remove = append(remove, rel)
	}
	sort.Strings(remove)
	state := map[string]any{
		"schemaVersion":    cliSchemaVersion,
		"toolVersion":      version,
		"packageId":        manifest.PackageID,
		"projectId":        manifest.ProjectID,
		"profileId":        manifest.ProfileID,
		"channel":          manifest.Channel,
		"version":          manifest.Version,
		"appliedAt":        time.Now().UTC().Format(time.RFC3339),
		"files":            applied,
		"rollbackSnapshot": snapshotID,
		"updaterCore":      "unified-transactional-updater/0.15.6",
	}
	stateRaw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	stateRaw = append(stateRaw, '\n')
	stateSize, stateSHA := updaterBytesMetadata0156(stateRaw)
	files = append(files, updaterFileSpec0156{Path: ".neverlauncher/client-state.json", Data: stateRaw, Size: stateSize, SHA256: stateSHA})

	updater, err := newTransactionalUpdater0156(clientDir)
	if err != nil {
		return nil, err
	}
	verifyFn := func() error {
		verify, err := verifyClientInstallation(packagePath, clientDir)
		if err != nil {
			return err
		}
		if !verify.Valid {
			return fmt.Errorf("клиент post-проверять ошибка: отсутствующий=%v повреждённый=%v", verify.Missing, verify.Corrupted)
		}
		return nil
	}
	tx, err := updater.apply(updaterRequest0156{
		Root:        clientDir,
		Namespace:   "client-package",
		FromVersion: clientInstalledVersion0156(clientDir),
		ToVersion:   manifest.Version,
		Files:       files,
		Remove:      remove,
		Verify:      verifyFn,
	})
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	return map[string]any{
		"schemaVersion": cliSchemaVersion,
		"toolVersion":   version,
		"packageId":     manifest.PackageID,
		"clientDir":     clientDir,
		"storageDir":    storageDir,
		"storagePrefix": prefix,
		"appliedFiles":  applied,
		"removedFiles":  remove,
		"appliedBytes":  appliedBytes,
		"stateFile":     statePath,
		"transaction":   tx,
		"status":        "transactionally-applied",
	}, nil
}

func clientInstalledVersion0156(clientDir string) string {
	raw, err := os.ReadFile(filepath.Join(clientDir, ".neverlauncher", "client-state.json"))
	if err != nil {
		return ""
	}
	var state struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &state) != nil {
		return ""
	}
	return strings.TrimSpace(state.Version)
}

func inferStoragePrefix(packagePath, storageDir string, manifest ClientPackageManifest) string {
	cleanPackage := filepath.Clean(packagePath)
	cleanStorage := filepath.Clean(storageDir)
	if rel, err := filepath.Rel(cleanStorage, filepath.Dir(cleanPackage)); err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Join("clients", manifest.ProjectID, manifest.ProfileID, manifest.Channel, manifest.Version))
}

func clientLocalState(clientDir, profile, channel string) (map[string]any, error) {
	statePath := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "clientDir": clientDir, "profileId": profile, "channel": channel, "stateFile": statePath, "status": "empty"}, nil
	}
	if err != nil {
		return nil, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	state["stateFile"] = statePath
	state["status"] = "ready"
	return state, nil
}

func validateClientPackagePath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.Contains(path, "\\") {
		return fmt.Errorf("небезопасный путь клиент пакет: %s", path)
	}
	lower := strings.ToLower(path)
	for _, forbidden := range []string{".env", "id_rsa", "id_ed25519", ".pem", ".key"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("запрещённый файл клиент пакет: %s", path)
		}
	}
	return nil
}

func copyFileAtomic(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, info.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func safeArtifactName(name string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(name)
}

func classifyClientFile(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "libraries/"):
		return "libraries", true
	case strings.HasPrefix(path, "assets/") || strings.HasPrefix(path, "resources/"):
		return "assets", true
	case strings.HasPrefix(path, "versions/") || strings.HasPrefix(path, "natives/"):
		return "runtime", true
	case strings.HasPrefix(path, "mods/optional/") || strings.HasPrefix(path, "optional/"):
		return "optional-mods", false
	case strings.HasPrefix(path, "mods/"):
		return "mods", true
	case strings.HasPrefix(path, "config/"):
		return "config", true
	default:
		return "root", true
	}
}

func isExecutablePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".sh") || strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".exe")
}

func countRequired(files []ClientPackageFile, required bool) int {
	count := 0
	for _, file := range files {
		if file.Required == required {
			count++
		}
	}
	return count
}
