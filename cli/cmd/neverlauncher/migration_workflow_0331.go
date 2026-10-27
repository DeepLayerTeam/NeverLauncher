package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Command execution is synchronous. A failed CLI process may be restarted;
// the database checkpoint and lease, not the CLI process, own progress.
func handleMigrationWorkflow0331(args []string) error {
	if len(args) < 1 {
		return errors.New("migrate gravit requires create|list|status|events|execute|pause|resume")
	}
	command := args[0]
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
	case "status", "events", "execute", "pause", "resume":
		id := strings.TrimSpace(flagValue(args, "--run", ""))
		if id == "" {
			return fmt.Errorf("%s requires --run", command)
		}
		path = base + "/" + url.PathEscape(id)
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
	return writeOrPrintJSON(out, result)
}
