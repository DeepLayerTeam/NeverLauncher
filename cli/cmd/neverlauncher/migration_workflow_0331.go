package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Command execution is synchronous. A failed CLI process may be restarted;
// the database checkpoint and lease, not the CLI process, own progress.
func handleMigrationWorkflow0331(args []string) error {
	if len(args) < 1 {
		return errors.New("migrate gravit requires create|list|status|events|execute|pause|resume|assess|compatibility|inventory|export|identities|map-identities|verify-identities|credentials|preview-credentials|import-credentials|security|preview-security|activate-security|content|preview-content|import-content|apply-optionals|modules|analyze-modules|enroll-serverbridge|rehearse|cutover-list|cutover-stage|cutover-activate|cutover-cancel|rollback-plan|rollback-commit|rollback-status|report|report-review|report-review-status|generate-never-keys")
	}
	command := args[0]
	if command == "report" || command == "report-review" || command == "report-review-status" {
		return handleMigrationReport03313(args)
	}
	if command == "rehearse" {
		return handleMigrationRehearsal03310(args[1:])
	}
	if strings.HasPrefix(command, "rollback-") {
		return handleMigrationRollback03312(args)
	}
	if strings.HasPrefix(command, "cutover-") {
		return handleMigrationCutover03311(args)
	}
	if command == "generate-never-keys" {
		return generateNeverMigrationKeys0336(flagValue(args, "--output", ""))
	}
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	if backend == "" || token == "" {
		return errors.New("migrate gravit requires --backend and --token (or NEVERLAUNCHER_TOKEN)")
	}
	out := flagValue(args, "--output", "")
	base := backend + "/api/v1/admin/migration-runs"
	var method = "GET"
	var path string
	var body any
	switch command {
	case "create":
		project := strings.TrimSpace(flagValue(args, "--project", ""))
		key := strings.TrimSpace(flagValue(args, "--key", ""))
		if project == "" || len(key) < 8 {
			return errors.New("create requires --project and a stable --key (8+ characters) for network retry safety")
		}
		method = "POST"
		path = base
		body = map[string]string{"projectId": project, "idempotencyKey": key, "sourceKind": "gravit"}
	case "list":
		project := strings.TrimSpace(flagValue(args, "--project", ""))
		if project == "" {
			return errors.New("list requires --project")
		}
		path = base + "?projectId=" + url.QueryEscape(project)
	case "status", "events", "execute", "pause", "resume", "assess", "compatibility", "inventory", "export", "identities", "map-identities", "verify-identities", "credentials", "preview-credentials", "import-credentials", "security", "preview-security", "activate-security", "content", "preview-content", "import-content", "apply-optionals", "modules", "analyze-modules", "enroll-serverbridge":
		id := strings.TrimSpace(flagValue(args, "--run", ""))
		if id == "" {
			return fmt.Errorf("%s requires --run", command)
		}
		path = base + "/" + url.PathEscape(id)
		if command == "modules" || command == "analyze-modules" || command == "enroll-serverbridge" {
			path += "/modules"
			if command == "analyze-modules" {
				return migrationModuleAnalyze0338(path+"/analyze", token, flagValue(args, "--source", ""), out)
			}
			if command == "enroll-serverbridge" {
				return migrationModuleEnroll0338(path+"/enroll-serverbridge", token, id, out, flagValue(args, "--wrapper", ""), flagValue(args, "--server-id", ""), flagValue(args, "--name", ""), flagValue(args, "--kind", ""), flagValue(args, "--profile-id", ""), flagValue(args, "--public-key", ""), flagValue(args, "--fresh-keys-confirmed", "") == "true")
			}
			break
		}
		if command == "content" || command == "preview-content" || command == "import-content" || command == "apply-optionals" {
			path += "/content"
			pp := flagValue(args, "--profile-path", "")
			if pp == "" {
				return errors.New("content requires --profile-path profiles/name.json")
			}
			if command == "content" {
				path += "?profilePath=" + url.QueryEscape(pp)
				break
			}
			if command == "apply-optionals" {
				path += "/apply-optionals?profilePath=" + url.QueryEscape(pp)
				method = "POST"
				return migrationApplyOptionalsCLI0337(path, token, id, out)
			}
			apply := command == "import-content"
			if apply {
				path += "/import"
			} else {
				path += "/preview"
			}
			return postMigrationContent0337(path, token, flagValue(args, "--source", ""), id, pp, flagValue(args, "--profile-id", ""), flagValue(args, "--name", ""), flagValue(args, "--loader", ""), flagValue(args, "--channel", "stable"), flagValue(args, "--version", ""), out, apply)
		}
		if command == "security" || command == "preview-security" || command == "activate-security" {
			path += "/security"
			if command == "preview-security" || command == "activate-security" {
				if command == "preview-security" {
					path += "/preview"
				} else {
					path += "/activate"
				}
				return postMigrationSecurity0336(path, token, id, out, command == "activate-security", flagValue(args, "--confirm", ""))
			}
		}
		if command == "credentials" || command == "preview-credentials" || command == "import-credentials" {
			path += "/credentials"
			if command == "preview-credentials" || command == "import-credentials" {
				apply := command == "import-credentials"
				if apply {
					path += "/import"
				} else {
					path += "/preview"
				}
				return postMigrationAuth0335(path, token, flagValue(args, "--source", ""), flagValue(args, "--fileauth-format", ""), id, out, apply)
			}
		}
		if command == "identities" || command == "map-identities" || command == "verify-identities" {
			path += "/identities"
			if command == "map-identities" {
				return postGravitInventory0333(path, token, flagValue(args, "--source", ""), out, false)
			}
			if command == "verify-identities" {
				method = "POST"
				path += "/verify"
				body = map[string]any{}
			}
		}
		if command == "inventory" || command == "export" {
			path += "/" + command
			source := flagValue(args, "--source", "")
			if command == "inventory" && source == "" {
				break
			}
			return postGravitInventory0333(path, token, source, out, command == "export")
		}
		if command == "assess" || command == "compatibility" {
			path += "/compatibility"
			if command == "assess" {
				return postGravitAssessment0332(path, token, flagValue(args, "--source", ""), flagValue(args, "--version", ""), out)
			}
		}
		if command == "events" {
			path += "/events"
			if cursor := flagValue(args, "--after", ""); cursor != "" {
				path += "?after=" + url.QueryEscape(cursor)
			}
		}
		if command == "execute" || command == "pause" || command == "resume" {
			method = "POST"
			path += "/" + command
			body = map[string]any{}
		}
	default:
		return fmt.Errorf("unknown migrate gravit command: %s", command)
	}
	result, err := httpJSONWithAuth(method, path, body, token)
	if err != nil {
		return err
	}
	if command == "identities" || command == "verify-identities" || command == "credentials" || command == "security" {
		return writePrivateIdentityReport0334(out, result)
	}
	return writeOrPrintJSON(out, result)
}

// postGravitAssessment0332 streams operator-selected bytes over a bounded HTTPS
// request. The backend never receives a host filesystem path or raw secrets in JSON.
func postGravitAssessment0332(endpoint, token, sourcePath, claimedVersion, out string) error {
	if sourcePath == "" {
		return errors.New("assess requires --source /path/to/gravit-installation.zip")
	}
	if len(claimedVersion) > 40 {
		return errors.New("invalid --version")
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
		return errors.New("ZIP must be a regular file of 1..64 MiB")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if u.Scheme != "http" || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("Gravit ZIP and admin token require HTTPS (except explicit IP loopback)")
		}
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	req, err := http.NewRequest("POST", endpoint, source)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	if claimedVersion != "" {
		req.Header.Set("X-Gravit-Version", claimedVersion)
	}
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	var payload map[string]any
	if err = json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("compatibility endpoint returned invalid JSON (HTTP %d)", response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("compatibility assessment HTTP %d: %v", response.StatusCode, payload["error"])
	}
	return writeOrPrintJSON(out, payload)
}
