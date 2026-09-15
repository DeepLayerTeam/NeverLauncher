package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func handlePipeline(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные pipeline-подкоманды: plan, channels, status, stage, smoke-test, publish, rollback, audit")
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
			return errors.New("pipeline plan требует --backend: план строится только относительно реального Backend API")
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
				"POST /api/v1/packages/{packageId}/smoke-test",
				"POST /api/v1/packages/{packageId}/publish",
				"POST /api/v1/channels/{channel}/rollback",
			},
		}
		return writeOrPrintJSON(out, payload)
	}
	if backend == "" {
		return errors.New("pipeline operation требует --backend")
	}
	if token == "" && args[0] != "channels" {
		return errors.New("pipeline operation требует --token или NEVERLAUNCHER_TOKEN")
	}

	switch args[0] {
	case "channels":
		if project == "" {
			return errors.New("pipeline channels требует --project")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/projects/"+url.PathEscape(project)+"/channels", nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "status":
		if packageID == "" {
			return errors.New("pipeline status требует --package-id")
		}
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/packages/"+url.PathEscape(packageID), nil, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "stage":
		if packageID == "" {
			return errors.New("pipeline stage требует --package-id")
		}
		validate, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/validate", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("package validation failed: %w", err)
		}
		sign, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/sign", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("package signing failed: %w", err)
		}
		staged, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/stage", map[string]any{}, token)
		if err != nil {
			return fmt.Errorf("package stage failed: %w", err)
		}
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "validate": validate, "sign": sign, "stage": staged})
	case "smoke-test":
		if packageID == "" {
			return errors.New("pipeline smoke-test требует --package-id")
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/smoke-test", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "publish":
		if packageID == "" {
			return errors.New("pipeline publish требует --package-id")
		}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/packages/"+url.PathEscape(packageID)+"/publish", map[string]any{}, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "rollback":
		if project == "" {
			return errors.New("pipeline rollback требует --project")
		}
		toVersion := flagValue(args, "--to", "")
		if toVersion == "" || toVersion == "previous" {
			return errors.New("pipeline rollback требует явный --to <version>; неявный previous запрещён")
		}
		body := map[string]any{"projectId": project, "profileId": profile, "toVersion": toVersion}
		payload, err := httpJSONWithAuth("POST", backend+"/api/v1/channels/"+url.PathEscape(channel)+"/rollback", body, token)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, payload)
	case "audit":
		if packageID == "" {
			return errors.New("pipeline audit требует --package-id")
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
		return errors.New("доступные client-подкоманды: install, update, verify, repair, cleanup, rollback, package-build, package-verify, upload-plan, package-upload, publish-channel, package-publish, package-release, package-status, channel-status, consume-plan, package-consume, package-apply, local-state, rollback-snapshot, package-pipeline, package-stage, package-smoke-test, package-promote")
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
			return fmt.Errorf("client verify failed: missing=%v corrupted=%v", report.Missing, report.Corrupted)
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
			return fmt.Errorf("небезопасный путь client package: %s", rel)
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
		return ClientPackageManifest{}, errors.New("client package manifest не содержит packageId")
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
			return nil, fmt.Errorf("%s: checksum/size mismatch before upload", file.Path)
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
			return nil, fmt.Errorf("%s: remote checksum/size mismatch", file.Path)
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
		return nil, fmt.Errorf("channel mismatch: package=%s requested=%s", manifest.Channel, channel)
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
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	prefix := inferStoragePrefix(packagePath, storageDir, manifest)
	applied := []map[string]any{}
	var appliedBytes int64
	for _, file := range manifest.Files {
		if err := validateClientPackagePath(file.Path); err != nil {
			return nil, err
		}
		src := filepath.Join(storageDir, filepath.FromSlash(prefix), filepath.FromSlash(file.Path))
		if _, err := os.Stat(src); err != nil {
			// Fallback: package manifest may be next to the uploaded files.
			src = filepath.Join(filepath.Dir(packagePath), filepath.FromSlash(file.Path))
		}
		sum, size, err := hashFile(src)
		if err != nil {
			return nil, fmt.Errorf("%s: storage object unavailable: %w", file.Path, err)
		}
		if sum != file.SHA256 || size != file.Size {
			return nil, fmt.Errorf("%s: storage object checksum/size mismatch", file.Path)
		}
		dst := filepath.Join(clientDir, filepath.FromSlash(file.Path))
		if err := copyFileAtomic(src, dst); err != nil {
			return nil, err
		}
		localSum, localSize, err := hashFile(dst)
		if err != nil {
			return nil, err
		}
		if localSum != file.SHA256 || localSize != file.Size {
			return nil, fmt.Errorf("%s: applied file checksum/size mismatch", file.Path)
		}
		appliedBytes += file.Size
		applied = append(applied, map[string]any{"path": file.Path, "sha256": file.SHA256, "size": file.Size, "status": "applied"})
	}
	state := map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "packageId": manifest.PackageID, "projectId": manifest.ProjectID, "profileId": manifest.ProfileID, "channel": manifest.Channel, "version": manifest.Version, "appliedAt": time.Now().UTC().Format(time.RFC3339), "files": applied}
	statePath := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	if err := writeJSONFile(statePath, state); err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "packageId": manifest.PackageID, "clientDir": clientDir, "storageDir": storageDir, "storagePrefix": prefix, "appliedFiles": applied, "appliedBytes": appliedBytes, "stateFile": statePath, "status": "applied"}, nil
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
		return fmt.Errorf("небезопасный путь client package: %s", path)
	}
	lower := strings.ToLower(path)
	for _, forbidden := range []string{".env", "id_rsa", "id_ed25519", ".pem", ".key"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("запрещённый файл client package: %s", path)
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
