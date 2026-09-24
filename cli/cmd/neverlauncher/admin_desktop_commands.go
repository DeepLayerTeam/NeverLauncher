package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func handleAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные admin-подкоманды: overview, users, roles, audit, storage-health, create-project, update-project, create-profile, update-profile, create-channel, update-channel, create-user")
	}
	backend := adminBackendURL(args)
	if backend == "" {
		return errors.New("admin-команды требуют --backend <url>")
	}
	out := flagValue(args, "--output", "")
	var payload map[string]any
	var err error
	switch args[0] {
	case "overview":
		payload, _, err = adminBackendGet(args, "/api/v1/admin/overview")
	case "users":
		payload, _, err = adminBackendGet(args, "/api/v1/admin/users")
	case "roles":
		payload, _, err = adminBackendGet(args, "/api/v1/admin/roles")
	case "audit":
		payload, _, err = adminBackendGet(args, "/api/v1/admin/audit")
	case "storage-health":
		payload, _, err = adminBackendGet(args, "/api/v1/admin/storage/health")
	case "create-project":
		body := map[string]any{"id": flagValue(args, "--project", "demo-project"), "name": flagValue(args, "--name", "Demo Project"), "description": flagValue(args, "--description", ""), "homepage": flagValue(args, "--homepage", ""), "repository": flagValue(args, "--repository", ""), "defaultChannel": flagValue(args, "--channel", "stable")}
		payload, _, err = adminBackendPost(args, "/api/v1/admin/projects", body)
	case "update-project":
		project := flagValue(args, "--project", "")
		if project == "" {
			return errors.New("update-project требует --project")
		}
		body := map[string]any{"name": flagValue(args, "--name", ""), "description": flagValue(args, "--description", ""), "homepage": flagValue(args, "--homepage", ""), "repository": flagValue(args, "--repository", ""), "defaultChannel": flagValue(args, "--channel", "")}
		payload, _, err = adminBackendPatch(args, "/api/v1/admin/projects/"+project, body)
	case "create-profile":
		project := flagValue(args, "--project", "")
		if project == "" {
			return errors.New("create-profile требует --project")
		}
		body := map[string]any{"id": flagValue(args, "--profile", "vanilla"), "name": flagValue(args, "--name", "Vanilla"), "description": flagValue(args, "--description", ""), "loader": flagValue(args, "--loader", "vanilla"), "preset": flagValue(args, "--preset", "recommended")}
		payload, _, err = adminBackendPost(args, "/api/v1/admin/projects/"+project+"/profiles", body)
	case "update-profile":
		project, profile := flagValue(args, "--project", ""), flagValue(args, "--profile", "")
		if project == "" || profile == "" {
			return errors.New("update-profile требует --project и --profile")
		}
		body := map[string]any{"name": flagValue(args, "--name", ""), "description": flagValue(args, "--description", ""), "loader": flagValue(args, "--loader", ""), "preset": flagValue(args, "--preset", "")}
		payload, _, err = adminBackendPatch(args, "/api/v1/admin/projects/"+project+"/profiles/"+profile, body)
	case "create-channel":
		project := flagValue(args, "--project", "")
		if project == "" {
			return errors.New("create-channel требует --project")
		}
		channel := flagValue(args, "--channel", "stable")
		body := map[string]any{"id": channel, "name": flagValue(args, "--name", channel), "description": flagValue(args, "--description", ""), "protected": flagValue(args, "--protected", "false") == "true"}
		payload, _, err = adminBackendPost(args, "/api/v1/admin/projects/"+project+"/channels", body)
	case "update-channel":
		project, channel := flagValue(args, "--project", ""), flagValue(args, "--channel", "")
		if project == "" || channel == "" {
			return errors.New("update-channel требует --project и --channel")
		}
		body := map[string]any{"name": flagValue(args, "--name", ""), "description": flagValue(args, "--description", ""), "protected": flagValue(args, "--protected", "false") == "true"}
		payload, _, err = adminBackendPatch(args, "/api/v1/admin/projects/"+project+"/channels/"+channel, body)
	case "create-user":
		email := flagValue(args, "--email", "")
		password := flagValue(args, "--password", "")
		if email == "" || password == "" {
			return errors.New("create-user требует --email и --password")
		}
		body := map[string]any{"email": email, "displayName": flagValue(args, "--name", email), "roleId": flagValue(args, "--role", "viewer"), "password": password}
		payload, _, err = adminBackendPost(args, "/api/v1/admin/users", body)
	default:
		return fmt.Errorf("неизвестная admin-подкоманда: %s", args[0])
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, payload)
}

func adminBackendURL(args []string) string {
	return strings.TrimRight(flagValue(args, "--backend", ""), "/")
}

func backendToken(args []string) string {
	if token := flagValue(args, "--token", ""); token != "" {
		return token
	}
	return os.Getenv("NEVERLAUNCHER_TOKEN")
}

func adminBackendGet(args []string, path string) (map[string]any, bool, error) {
	backend := adminBackendURL(args)
	if backend == "" {
		return nil, false, nil
	}
	payload, err := httpJSONWithAuth("GET", backend+path, nil, backendToken(args))
	if err != nil {
		return nil, true, err
	}
	return payload, true, nil
}

func adminBackendPost(args []string, path string, body map[string]any) (map[string]any, bool, error) {
	return adminBackendRequest(args, "POST", path, body)
}

func adminBackendPatch(args []string, path string, body map[string]any) (map[string]any, bool, error) {
	return adminBackendRequest(args, "PATCH", path, body)
}

func adminBackendRequest(args []string, method string, path string, body map[string]any) (map[string]any, bool, error) {
	backend := adminBackendURL(args)
	if backend == "" {
		return nil, false, nil
	}
	payload, err := httpJSONWithAuth(method, backend+path, body, backendToken(args))
	if err != nil {
		return nil, true, err
	}
	return payload, true, nil
}

func handleDesktop(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные desktop-подкоманды: connect, config, platforms, package, verify")
	}
	switch args[0] {
	case "connect":
		return desktopFirstRunConnect(args)
	case "config":
		return writeOrPrintJSON(flagValue(args, "--output", ""), desktopConfigModel(args))
	case "platforms":
		printJSON(map[string]any{"version": version, "platforms": desktopPackagePlatforms(version)})
		return nil
	case "package":
		ver := flagValue(args, "--version", version)
		out := flagValue(args, "--out", filepath.Join("dist", "desktop-package-"+ver))
		artifactDir := flagValue(args, "--artifact-dir", filepath.Join("dist", "release-"+ver))
		return buildDesktopPackage(ver, artifactDir, out, flagValue(args, "--platform", "all"))
	case "verify":
		if len(args) < 2 {
			return errors.New("desktop verify требует путь к каталогу desktop package")
		}
		return verifyDesktopPackage(args[1])
	default:
		return fmt.Errorf("неизвестная desktop-подкоманда: %s", args[0])
	}
}

func desktopFirstRunConnect(args []string) error {
	out := flagValue(args, "--output", "")
	backend, _, _, _, _ := desktopBackendArgs(args)
	checks := []map[string]any{}
	status := "ok"
	if res, err := httpJSON("GET", backend+"/health", nil); err == nil {
		checks = append(checks, map[string]any{"id": "health", "status": "ok", "response": res})
	} else {
		status = "failed"
		checks = append(checks, map[string]any{"id": "health", "status": "failed", "error": err.Error()})
	}
	if res, err := httpJSON("GET", backend+"/ready", nil); err == nil {
		checks = append(checks, map[string]any{"id": "ready", "status": "ok", "response": res})
	} else {
		status = "failed"
		checks = append(checks, map[string]any{"id": "ready", "status": "failed", "error": err.Error()})
	}
	return writeOrPrintJSON(out, map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "mode": "desktop-first-run-connect", "backend": backend, "status": status, "checks": checks})
}

func desktopPackagePlatforms(ver string) []DesktopPackagePlatform {
	items := []DesktopPackagePlatform{}
	if linuxProductionRequired0153(ver) {
		items = append(items,
			DesktopPackagePlatform{OS: "linux", Arch: "x64", Format: "binary", Artifact: "neverlauncher-desktop-linux-x64", Status: "supported"},
			DesktopPackagePlatform{OS: "linux", Arch: "x64", Format: "tar.gz", Artifact: "neverlauncher-linux-x64-" + ver + ".tar.gz", Status: "supported"},
			DesktopPackagePlatform{OS: "linux", Arch: "arm64", Format: "binary", Artifact: "neverlauncher-desktop-linux-arm64", Status: "supported"},
			DesktopPackagePlatform{OS: "linux", Arch: "arm64", Format: "tar.gz", Artifact: "neverlauncher-linux-arm64-" + ver + ".tar.gz", Status: "supported"},
		)
	} else {
		items = append(items,
			DesktopPackagePlatform{OS: "linux", Arch: "x64", Format: "binary", Artifact: "neverlauncher-desktop-linux-amd64", Status: "supported"},
			DesktopPackagePlatform{OS: "linux", Arch: "x64", Format: "AppImage", Artifact: "neverlauncher-desktop-" + ver + "-linux-amd64.AppImage", Status: "supported-if-built"},
			DesktopPackagePlatform{OS: "linux", Arch: "x64", Format: "deb", Artifact: "neverlauncher-desktop-" + ver + "-linux-amd64.deb", Status: "supported-if-built"},
		)
	}
	items = append(items,
		DesktopPackagePlatform{OS: "windows", Arch: "x64", Format: "exe", Artifact: "neverlauncher-desktop-windows-x64.exe", Status: "supported"},
		DesktopPackagePlatform{OS: "windows", Arch: "x64", Format: "zip", Artifact: "neverlauncher-desktop-" + ver + "-windows-x64.zip", Status: "supported"},
		DesktopPackagePlatform{OS: "windows", Arch: "arm64", Format: "exe", Artifact: "neverlauncher-desktop-windows-arm64.exe", Status: "supported"},
		DesktopPackagePlatform{OS: "windows", Arch: "arm64", Format: "zip", Artifact: "neverlauncher-desktop-" + ver + "-windows-arm64.zip", Status: "supported"},
	)
	if macOSProductionRequired0154(ver) {
		items = append(items,
			DesktopPackagePlatform{OS: "macos", Arch: "x64", Format: "binary", Artifact: "neverlauncher-desktop-macos-x64", Status: "supported"},
			DesktopPackagePlatform{OS: "macos", Arch: "x64", Format: "zip", Artifact: "neverlauncher-desktop-" + ver + "-macos-x64.zip", Status: "supported"},
			DesktopPackagePlatform{OS: "macos", Arch: "arm64", Format: "binary", Artifact: "neverlauncher-desktop-macos-arm64", Status: "supported"},
			DesktopPackagePlatform{OS: "macos", Arch: "arm64", Format: "zip", Artifact: "neverlauncher-desktop-" + ver + "-macos-arm64.zip", Status: "supported"},
		)
	} else {
		items = append(items, DesktopPackagePlatform{OS: "macos", Arch: "universal", Format: "zip", Artifact: "neverlauncher-desktop-" + ver + "-macos-universal.zip", Status: "supported-if-built"})
	}
	return items
}

func filterDesktopPlatforms(items []DesktopPackagePlatform, platform string) []DesktopPackagePlatform {
	if platform == "" || platform == "all" {
		return items
	}
	var filtered []DesktopPackagePlatform
	for _, item := range items {
		if item.OS == platform || item.Format == platform || item.OS+"-"+item.Arch == platform {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func handlePackaging(args []string) error {
	if len(args) < 1 {
		return errors.New("доступные packaging-подкоманды: prepare, verify, sign")
	}
	out := flagValue(args, "--output", "")
	switch args[0] {
	case "prepare", "build":
		root := flagValue(args, "--root", ".")
		dir := flagValue(args, "--out", filepath.Join("dist", "neverlauncher-production-"+version))
		if err := packaging940Prepare(root, dir); err != nil {
			return err
		}
		fmt.Printf("Production packaging bundle prepared: %s\n", dir)
		return nil
	case "verify":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("packaging verify требует путь к release bundle")
		}
		report, err := packaging940Verify(dir)
		if err != nil {
			return err
		}
		return writeOrPrintJSON(out, report)
	case "sign":
		dir := flagValue(args, "--bundle", "")
		if dir == "" && len(args) > 1 && !strings.HasPrefix(args[1], "--") {
			dir = args[1]
		}
		if dir == "" {
			return errors.New("packaging sign требует путь к release bundle")
		}
		if err := signReleaseBundle(dir, flagValue(args, "--private-key", "")); err != nil {
			return err
		}
		return writeOrPrintJSON(out, map[string]any{"schemaVersion": "1.0", "toolVersion": version, "status": "signed", "signature": "SHA256SUMS.sig", "algorithm": "Ed25519"})
	default:
		return fmt.Errorf("неизвестная packaging-подкоманда: %s", args[0])
	}
}

func packaging940ReleaseGates() []map[string]any {
	return []map[string]any{
		{"id": "version-matrix", "required": true, "status": "required", "check": "VERSION, CLI, API, Admin, Desktop, Tauri, OpenAPI must equal 0.10.0"},
		{"id": "backend-build", "required": true, "status": "required", "check": "go build -tags neverlauncher_nopgx ./cmd/neverlauncher-api"},
		{"id": "cli-build", "required": true, "status": "required", "check": "go build ./cmd/neverlauncher"},
		{"id": "admin-build", "required": true, "status": "required", "check": "npm ci && npm run build --prefix apps/admin"},
		{"id": "desktop-web-build", "required": true, "status": "required", "check": "npm ci && npm run build --prefix apps/desktop"},
		{"id": "tauri-native-build", "required": true, "status": "external", "check": "cargo/tauri build on Linux/Windows/macOS runner"},
		{"id": "checksums", "required": true, "status": "implemented", "check": "SHA256SUMS generated and verified"},
		{"id": "sbom", "required": true, "status": "implemented", "check": "SBOM.spdx.json present"},
		{"id": "provenance", "required": true, "status": "implemented", "check": "PROVENANCE.json present"},
		{"id": "artifact-manifest", "required": true, "status": "implemented", "check": "RELEASE_MANIFEST.json and ARTIFACTS.json present"},
		{"id": "packaging-smoke", "required": true, "status": "implemented", "check": "nl packaging smoke"},
	}
}

func packaging940Prepare(srcRoot, outDir string) error {
	absRoot, err := filepath.Abs(srcRoot)
	if err != nil {
		return err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(absOut); err != nil {
		return err
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return err
	}
	artifactDir := filepath.Join(absOut, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return err
	}
	candidates := []string{"VERSION", "README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE", "NOTICE", "schemas/openapi.yaml", "cli/nl", "services/api/neverlauncher-api", "apps/admin/package.json", "apps/admin/package-lock.json", "apps/desktop/package.json", "apps/desktop/package-lock.json", "apps/desktop/src-tauri/tauri.conf.json", "apps/desktop/src-tauri/Cargo.toml"}
	entries := []map[string]any{}
	for _, rel := range candidates {
		src := filepath.Join(absRoot, filepath.FromSlash(rel))
		st, err := os.Stat(src)
		if err != nil || st.IsDir() {
			continue
		}
		dstRel := filepath.ToSlash(filepath.Join("artifacts", rel))
		dst := filepath.Join(absOut, filepath.FromSlash(dstRel))
		if err := packaging940CopyFile(src, dst); err != nil {
			return err
		}
		sum, size, err := hashFile(dst)
		if err != nil {
			return err
		}
		entries = append(entries, map[string]any{"path": dstRel, "source": rel, "sha256": sum, "size": size, "required": true})
	}
	sort.Slice(entries, func(i, j int) bool { return fmt.Sprint(entries[i]["path"]) < fmt.Sprint(entries[j]["path"]) })
	if len(entries) < 5 {
		return fmt.Errorf("production packaging source incomplete: only %d artifacts collected", len(entries))
	}
	if err := writeJSONFile(filepath.Join(absOut, "SBOM.spdx.json"), packaging940SBOM(entries)); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(absOut, "PROVENANCE.json"), packaging940Provenance(srcRoot)); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(absOut, "BUILD_MATRIX.json"), packaging940BuildMatrix()); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(absOut, "ARTIFACTS.json"), map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "artifacts": entries}); err != nil {
		return err
	}
	manifest := map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "name": "NeverLauncher", "version": version, "mode": "production-packaging", "createdAt": time.Now().UTC().Format(time.RFC3339), "artifacts": entries, "releaseGates": packaging940ReleaseGates(), "requiredFiles": []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SBOM.spdx.json", "PROVENANCE.json", "BUILD_MATRIX.json", "ARTIFACTS.json"}}
	if err := writeJSONFile(filepath.Join(absOut, "RELEASE_MANIFEST.json"), manifest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(absOut, "RELEASE_NOTES.txt"), []byte(packaging940Description()), 0o644); err != nil {
		return err
	}
	checksums, err := packaging940Checksums(absOut)
	if err != nil {
		return err
	}
	if len(checksums) == 0 {
		return errors.New("SHA256SUMS is empty")
	}
	if err := os.WriteFile(filepath.Join(absOut, "SHA256SUMS"), []byte(strings.Join(checksums, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func packaging940CopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func packaging940Checksums(dir string) ([]string, error) {
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "SHA256SUMS" || rel == "SHA256SUMS.sig" {
			return nil
		}
		sum, _, err := hashFile(path)
		if err != nil {
			return err
		}
		lines = append(lines, sum+"  "+rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(lines)
	return lines, nil
}

func packaging940Verify(dir string) (map[string]any, error) {
	required := []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SBOM.spdx.json", "PROVENANCE.json", "BUILD_MATRIX.json", "ARTIFACTS.json", "RELEASE_NOTES.txt"}
	errs := []string{}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			errs = append(errs, "missing "+name)
		}
	}
	verified := 0
	if data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				errs = append(errs, "bad checksum line: "+line)
				continue
			}
			expected, rel := parts[0], parts[1]
			actual, _, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
			if err != nil {
				errs = append(errs, "cannot hash "+rel+": "+err.Error())
				continue
			}
			if actual != expected {
				errs = append(errs, "checksum mismatch: "+rel)
				continue
			}
			verified++
		}
	} else {
		errs = append(errs, "cannot read SHA256SUMS: "+err.Error())
	}
	status := "verified"
	if len(errs) > 0 {
		status = "failed"
	}
	report := map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "status": status, "verifiedFiles": verified, "errors": errs, "checkedAt": time.Now().UTC().Format(time.RFC3339)}
	if len(errs) > 0 {
		return report, errors.New(strings.Join(errs, "; "))
	}
	return report, nil
}

func packaging940SBOM(entries []map[string]any) map[string]any {
	pkgs := []map[string]any{}
	for _, e := range entries {
		pkgs = append(pkgs, map[string]any{"SPDXID": "SPDXRef-" + strings.NewReplacer("/", "-", ".", "-").Replace(fmt.Sprint(e["source"])), "name": fmt.Sprint(e["source"]), "versionInfo": version, "filesAnalyzed": true, "checksums": []map[string]string{{"algorithm": "SHA256", "checksumValue": fmt.Sprint(e["sha256"])}}})
	}
	return map[string]any{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "NeverLauncher " + version, "documentName": "NeverLauncher-" + version, "dataLicense": "CC0-1.0", "creationInfo": map[string]any{"created": time.Now().UTC().Format(time.RFC3339), "creators": []string{"Tool: NeverLauncher CLI " + version}}, "packages": pkgs}
}

func packaging940Provenance(srcRoot string) map[string]any {
	return map[string]any{"schemaVersion": "0.10.0", "subject": "NeverLauncher", "version": version, "builder": "NeverLauncher CLI production packaging 0.10.0", "sourceRoot": srcRoot, "generatedAt": time.Now().UTC().Format(time.RFC3339), "commands": []string{"nl release doctor", "nl db migration-doctor", "nl packaging prepare", "nl packaging verify", "nl packaging smoke"}, "materials": []string{"VERSION", "CLI binary", "Backend API binary", "Admin package metadata", "Desktop package metadata", "OpenAPI", "README", "CHANGELOG", "SECURITY"}}
}

func packaging940BuildMatrix() map[string]any {
	return map[string]any{"schemaVersion": "0.10.0", "toolVersion": version, "targets": []map[string]any{{"id": "backend-linux-amd64", "required": true, "command": "go build -tags neverlauncher_nopgx -o services/api/neverlauncher-api ./cmd/neverlauncher-api"}, {"id": "cli-linux-amd64", "required": true, "command": "go build -o cli/nl ./cmd/neverlauncher"}, {"id": "admin-web", "required": true, "command": "npm ci --prefix apps/admin && npm run build --prefix apps/admin"}, {"id": "desktop-web", "required": true, "command": "npm ci --prefix apps/desktop && npm run build --prefix apps/desktop"}, {"id": "tauri-linux", "required": true, "external": true, "command": "cargo tauri build"}, {"id": "tauri-windows", "required": true, "external": true, "command": "cargo tauri build --target x86_64-pc-windows-msvc"}, {"id": "tauri-macos", "required": true, "external": true, "command": "cargo tauri build --target universal-apple-darwin"}}}
}

func packaging940Description() string {
	return "# NeverLauncher 0.10.0 — Production Packaging\n\nРелиз закрепляет проверяемый production packaging: RELEASE_MANIFEST.json, SHA256SUMS, SBOM.spdx.json, PROVENANCE.json, BUILD_MATRIX.json, ARTIFACTS.json, smoke-signature и offline packaging smoke.\n"
}
