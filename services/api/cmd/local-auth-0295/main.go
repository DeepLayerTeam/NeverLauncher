// launcher-local-auth is a production operator CLI. Import runs offline
// against PostgreSQL; all ordinary account changes use the running API so
// session revocation, RBAC, MFA and audit remain server-authoritative.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "local-auth:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer, input io.Reader) error {
	if len(args) == 0 {
		return errors.New("usage: local-auth (import|list|export|create|password|disable|enable) [flags]")
	}
	switch args[0] {
	case "import":
		flags := flag.NewFlagSet("import", flag.ContinueOnError)
		path := flags.String("file", "", "FileAuthSystem Database.json path; never Sessions.json")
		format := flags.String("format", "", "explicit legacy password format")
		apply := flags.Bool("apply", false, "commit import (default: rollback after dry-run)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || filepath.Base(*path) != "Database.json" {
			return errors.New("provide exact FileAuthSystem Database.json with --file")
		}
		fd, err := os.Open(*path)
		if err != nil {
			return err
		}
		defer fd.Close()
		records, err := fileauth.Parse(fd, *format)
		if err != nil {
			return err
		}
		dsn := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_DATABASE_DSN"))
		if dsn == "" {
			dsn = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_DATABASE_URL"))
		}
		if dsn == "" {
			return errors.New("NEVERLAUNCHER_DATABASE_DSN is required")
		}
		repo := repository.NewSQLRepository("pgx", dsn, "")
		migrator, ok := repo.(interface {
			MigrationStatus(context.Context) (dbmigrate.Status, error)
		})
		if !ok {
			return errors.New("PostgreSQL migration checker unavailable")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		status, err := migrator.MigrationStatus(ctx)
		if err != nil {
			return fmt.Errorf("check schema: %w", err)
		}
		if !status.Compatible || len(status.Pending) != 0 {
			return errors.New("database schema has missing migrations; import refused")
		}
		importer, ok := repo.(repository.FileAuthImporter0295)
		if !ok {
			return errors.New("PostgreSQL atomic importer unavailable")
		}
		count, err := importer.ImportFileAuth0295(ctx, records, !*apply)
		if err != nil {
			return err
		}
		state := "validated; transaction rolled back"
		if *apply {
			state = "committed"
		}
		_, err = fmt.Fprintf(output, "FileAuthSystem: %d accounts %s; no Sessions.json imported\n", count, state)
		return err
	case "list", "export", "create", "password", "disable", "enable":
		return runOnline(args, output, input)
	default:
		return fmt.Errorf("unknown local-auth command %q", args[0])
	}
}

func runOnline(args []string, output io.Writer, input io.Reader) error {
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	endpoint := flags.String("api", os.Getenv("NEVERLAUNCHER_API_URL"), "HTTPS Backend URL")
	tokenEnv := flags.String("token-env", "NEVERLAUNCHER_ADMIN_ACCESS_TOKEN", "environment variable containing admin Bearer token")
	email := flags.String("email", "", "new account email")
	displayName := flags.String("name", "", "display name")
	role := flags.String("role", "player", "new account role")
	userID := flags.String("user-id", "", "target Never user ID")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments (passwords must only arrive over stdin)")
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(*endpoint), "/"))
	if err != nil {
		return err
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1")) {
		return errors.New("API must use HTTPS (or localhost for development)")
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("invalid API URL")
	}
	token := strings.TrimSpace(os.Getenv(*tokenEnv))
	if token == "" {
		return fmt.Errorf("missing token environment variable %s", *tokenEnv)
	}
	var method, path string
	var payload any
	switch command {
	case "list", "export":
		method, path = "GET", "/api/v1/admin/users"
	case "create":
		if *email == "" || strings.Contains(*email, "@"+fileauth.EmailDomain) || (*role != "player" && *role != "viewer") {
			return errors.New("create requires --email and an unprivileged --role (player|viewer)")
		}
		password, err := readPassword(input)
		if err != nil {
			return err
		}
		method, path = "POST", "/api/v1/admin/users"
		payload = map[string]any{"email": *email, "displayName": *displayName, "roleId": *role, "password": password}
	case "password":
		if *userID == "" {
			return errors.New("password requires --user-id")
		}
		password, err := readPassword(input)
		if err != nil {
			return err
		}
		method, path = "POST", "/api/v1/admin/users/"+url.PathEscape(*userID)+"/password"
		payload = map[string]any{"password": password}
	case "disable", "enable":
		if *userID == "" {
			return fmt.Errorf("%s requires --user-id", command)
		}
		method, path = "POST", "/api/v1/admin/users/"+url.PathEscape(*userID)+"/"+command
	}
	var data []byte
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(base.String(), "/")+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API rejected %s with HTTP %d (details in server audit)", command, resp.StatusCode)
	}
	// Prevent a future API field from accidentally exporting credentials.
	var result struct {
		Items []model.User `json:"items"`
		User  model.User   `json:"user"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if command == "list" || command == "export" {
		clean := make([]map[string]any, 0, len(result.Items))
		for _, u := range result.Items {
			clean = append(clean, map[string]any{"id": u.ID, "email": u.Email, "displayName": u.DisplayName, "roleId": u.RoleID, "status": u.Status})
		}
		return json.NewEncoder(output).Encode(map[string]any{"accounts": clean})
	}
	_, err = fmt.Fprintf(output, "%s: success; sessions and auditing handled by Backend\n", command)
	return err
}

func readPassword(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", errors.New("password input too long")
	}
	pwd := strings.TrimSuffix(string(raw), "\n")
	pwd = strings.TrimSuffix(pwd, "\r")
	if len(pwd) < 12 {
		return "", errors.New("password must contain at least 12 bytes")
	}
	return pwd, nil
}
