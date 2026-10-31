package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// CLI uses the exact HTTP operations lifecycle used by Admin and third-party SDKs.
// The backend remains the sole authority for permissions, MFA and step-up.
func handleDurableOperation0217(args []string) error {
	if len(args) == 0 {
		return errors.New("operation subcommands: registry, validate, execute, status, attempts, cancel, retry")
	}
	if adminBackendURL(args) == "" {
		return errors.New("--backend is required")
	}
	out := flagValue(args, "--output", "")
	var result map[string]any
	var err error
	switch args[0] {
	case "registry":
		result, _, err = adminBackendGet(args, "/api/v1/operations")
	case "validate", "execute":
		kind := strings.TrimSpace(flagValue(args, "--kind", ""))
		project := strings.TrimSpace(flagValue(args, "--project", ""))
		if kind == "" || project == "" {
			return errors.New("--kind and --project are required")
		}
		body := map[string]any{"kind": kind, "projectId": project,
			"resourceId":     flagValue(args, "--resource", flagValue(args, "--package", "")),
			"profileId":      flagValue(args, "--profile", "vanilla"),
			"channel":        flagValue(args, "--channel", ""),
			"toVersion":      flagValue(args, "--to-version", ""),
			"idempotencyKey": flagValue(args, "--key", "")}
		result, _, err = adminBackendPost(args, "/api/v1/operations/"+args[0], body)
	case "status", "attempts", "cancel", "retry":
		id := strings.TrimSpace(flagValue(args, "--id", ""))
		if id == "" {
			return errors.New("--id <operationId> is required")
		}
		path := "/api/v1/operations/" + url.PathEscape(id)
		if args[0] == "attempts" {
			path += "/attempts"
			result, _, err = adminBackendGet(args, path)
		} else if args[0] == "status" {
			result, _, err = adminBackendGet(args, path)
		} else {
			result, _, err = adminBackendPost(args, path+"/"+args[0], nil)
		}
	default:
		return fmt.Errorf("unknown operation subcommand: %s", args[0])
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(out, result)
}
