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
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// LiveIntegrationAudit0491 намеренно НЕ продвигает состояние миграции проекта.
// Он проверяет согласованность реальной строки PostgreSQL, аутентифицированного Go
// API и *настоящего RPC-ответа* установленного Java Host. Одной успешной
// готовности API /ready или кэшированного heartbeat супервизора недостаточно.
// SQL-транзакция выполняется только для чтения, в том числе в production.
type LiveIntegrationAudit0491 struct {
	Format                 string    `json:"format"`
	CheckedAt              time.Time `json:"checkedAt"`
	Backend                string    `json:"backend"`
	BackendVersion         string    `json:"backendVersion"`
	ProjectID              string    `json:"projectId"`
	MigrationRunID         string    `json:"migrationRunId"`
	MigrationRevision      int64     `json:"migrationRevision"`
	MigrationStatus        string    `json:"migrationStatus"`
	ExtensionID            string    `json:"extensionId"`
	Scope                  string    `json:"scope"`
	ScopeID                string    `json:"scopeId"`
	JavaVersion            string    `json:"javaVersion"`
	JavaInstanceID         string    `json:"javaInstanceId"`
	JavaGeneration         int64     `json:"javaGeneration"`
	PostgreSQLReadOnly     bool      `json:"postgresqlReadOnly"`
	PostgreSQLClientSHA256 string    `json:"postgresqlClientSha256"`
	Result                 string    `json:"result"`
}

type liveIntegrationOptions0491 struct {
	Backend, Project, Run, Extension, Scope, ScopeID, DSN, Token, PSQL, Output string
}

var auditIdentifier0491 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func integrationAuditCommand0491(args []string) error {
	fs := flag.NewFlagSet("integration-audit", flag.ContinueOnError)
	backend := fs.String("backend", "", "HTTPS-адрес источника Backend (или числовой loopback HTTP)")
	project := fs.String("project", "", "Идентификатор существующего проекта")
	run := fs.String("run", "", "Идентификатор существующего запуска миграции Gravit")
	extension := fs.String("extension", "", "Идентификатор установленного работающего расширения Java Host")
	scope := fs.String("scope", "global", "global или project")
	scopeID := fs.String("scope-id", "", "Идентификатор проекта для расширения с областью действия project")
	dsnEnv := fs.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Переменная окружения с DSN PostgreSQL")
	psql := fs.String("psql", "psql", "Путь к исполняемому файлу psql")
	output := fs.String("output", "", "Новый приватный JSON-файл свидетельств")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" || !validEnvironmentName0491(*dsnEnv) {
		return errors.New("--output, --dsn-env and no trailing arguments are required")
	}
	opts := liveIntegrationOptions0491{*backend, *project, *run, *extension, *scope, *scopeID, os.Getenv(*dsnEnv), os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"), *psql, *output}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	return executeIntegrationAudit0491(ctx, opts)
}

var auditEnv0491 = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validEnvironmentName0491(s string) bool { return auditEnv0491.MatchString(s) }
func validAuditScope0491(s, scopeID, project string) bool {
	if s == "global" {
		return scopeID == ""
	}
	return s == "project" && scopeID == project
}

// psql вызывается без shell и DSN в argv. libpq получает DSN через
// PGDATABASE. SQL содержит только запросы чтения и безопасно экранированные
// идентификаторы, без изменения схемы, временных таблиц или прав записи.
func postgresSnapshot0491(ctx context.Context, opts liveIntegrationOptions0491) (pgAudit0491, string, error) {
	var record pgAudit0491
	exe, err := exec.LookPath(opts.PSQL)
	if err != nil {
		return record, "", fmt.Errorf("psql executable missing: %w", err)
	}
	executableSHA, err := shaFile(exe, 256<<20)
	if err != nil {
		return record, "", fmt.Errorf("Не удалось подтвердить подлинность исполняемого файла psql: %w", err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	sql := `BEGIN READ ONLY;\nSELECT json_build_object(\n` +
		`'readOnly',current_setting('transaction_read_only'),` +
		`'project',(SELECT id FROM projects WHERE id=` + quote(opts.Project) + `),` +
		`'migration',(SELECT row_to_json(m) FROM (SELECT id,project_id,source_kind,status,step,revision FROM migration_runs_0331 WHERE id=` + quote(opts.Run) + `) m),` +
		`'extension',(SELECT row_to_json(e) FROM (SELECT extension_id,scope,scope_id,current_version,current_state,generation,enabled FROM extension_installs WHERE extension_id=` + quote(opts.Extension) + ` AND scope=` + quote(opts.Scope) + ` AND scope_id=` + quote(opts.ScopeID) + `) e)` +
		`)::text;\nCOMMIT;\n`
	// Настоящие переводы строк, а не экранированные SQL-литералы.
	sql = strings.ReplaceAll(sql, `\n`, "\n")
	cmd := exec.CommandContext(ctx, exe, "--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Env = append(withoutPostgresEnvironment0491(os.Environ(), opts), "PGDATABASE="+opts.DSN, "PGCONNECT_TIMEOUT=7", "PGOPTIONS=-c default_transaction_read_only=on")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return record, "", fmt.Errorf("read-only PostgreSQL transaction failed (psql exit: %v)", err)
	} // redact stderr: may include DSN
	if stdout.Len() > 16<<10 {
		return record, "", errors.New("oversized PostgreSQL audit response")
	}
	if err = json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &record); err != nil {
		return record, "", errors.New("invalid PostgreSQL JSON readback")
	}
	if record.ReadOnly != "on" || record.Project != opts.Project || record.Migration == nil || record.Extension == nil {
		return record, "", errors.New("PostgreSQL missing project/migration/extension or transaction not read-only")
	}
	return record, executableSHA, nil
}
func withoutPostgresEnvironment0491(env []string, opts liveIntegrationOptions0491) []string {
	out := make([]string, 0, len(env))
	for _, v := range env {
		key, value, _ := strings.Cut(v, "=")
		// Не передавать bearer авторизации API или вторую копию
		// учётных данных PostgreSQL внешнему клиентскому процессу.
		if strings.HasPrefix(key, "PG") || strings.HasPrefix(key, "LAUNCHER_MIGRATION_GA_") || key == "LAUNCHER_POSTGRES_DSN" || value == opts.Token || value == opts.DSN {
			continue
		}
		out = append(out, v)
	}
	return out
}

type pgAudit0491 struct {
	ReadOnly  string `json:"readOnly"`
	Project   string `json:"project"`
	Migration *struct {
		ID         string `json:"id"`
		ProjectID  string `json:"project_id"`
		SourceKind string `json:"source_kind"`
		Status     string `json:"status"`
		Step       string `json:"step"`
		Revision   int64  `json:"revision"`
	} `json:"migration"`
	Extension *struct {
		ExtensionID    string `json:"extension_id"`
		Scope          string `json:"scope"`
		ScopeID        string `json:"scope_id"`
		CurrentVersion string `json:"current_version"`
		CurrentState   string `json:"current_state"`
		Generation     int64  `json:"generation"`
		Enabled        bool   `json:"enabled"`
	} `json:"extension"`
}
type migrationAuditRun0491 struct {
	ID         string `json:"id"`
	ProjectID  string `json:"projectId"`
	SourceKind string `json:"sourceKind"`
	Status     string `json:"status"`
	Step       string `json:"step"`
	Revision   int64  `json:"revision"`
}
type hostAudit0491 struct {
	ExtensionID string `json:"extensionId"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId"`
	Version     string `json:"version"`
	Generation  int64  `json:"generation"`
	InstanceID  string `json:"instanceId"`
	Runtime     string `json:"runtime"`
	State       string `json:"state"`
	Healthy     bool   `json:"healthy"`
}
type hostProbe0491 struct {
	Host hostAudit0491 `json:"host"`
	Java struct {
		State      string `json:"state"`
		Responsive bool   `json:"responsive"`
	} `json:"java"`
}

func auditGet0491(ctx context.Context, client *http.Client, endpoint, token string, out any) error {
	// Существующие ответы Backend несут дополнительные версионированные поля. Сохранить
	// проверку оболочки ответа, затем декодировать только известную проекцию аудита.
	var raw json.RawMessage
	if err := getJSON(ctx, client, endpoint, token, &raw); err != nil {
		return err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("empty Backend projection")
	}
	return json.Unmarshal(raw, out)
}
func auditProbe0491(ctx context.Context, client *http.Client, endpoint, token string) (hostProbe0491, error) {
	var result hostProbe0491
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return result, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return result, fmt.Errorf("Java probe request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return result, fmt.Errorf("live Java probe refused HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil {
		return result, err
	}
	if len(data) > 64<<10 {
		return result, errors.New("Java probe response oversized")
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal(data, &envelope); err != nil {
		return result, err
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return result, errors.New("missing Java probe payload")
	}
	if err = json.Unmarshal(envelope.Data, &result); err != nil {
		return result, err
	}
	return result, nil
}

func executeIntegrationAudit0491(ctx context.Context, opts liveIntegrationOptions0491) error {
	if err := checkBackendURL(opts.Backend); err != nil {
		return err
	}
	for _, s := range []string{opts.Project, opts.Run, opts.Extension} {
		if !auditIdentifier0491.MatchString(s) {
			return errors.New("invalid project/run/extension identifier")
		}
	}
	if !validAuditScope0491(opts.Scope, opts.ScopeID, opts.Project) || opts.DSN == "" || opts.Token == "" {
		return errors.New("invalid scope, PostgreSQL DSN or admin token")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Готовность Backend должна включать действующий ping PostgreSQL и состояние схемы.
	var ready struct {
		Status     string            `json:"status"`
		Version    string            `json:"version"`
		Repository string            `json:"repository"`
		Checks     map[string]string `json:"checks"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.Backend+"/ready", nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Backend readiness failed: %w", err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return fmt.Errorf("Backend not ready HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<10+1))
	res.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > 16<<10 || json.Unmarshal(body, &ready) != nil || ready.Status != "ready" || ready.Repository != "postgres" || ready.Checks["repository"] != "ok" || ready.Checks["migrations"] == "" {
		return errors.New("Backend does not report a live migrated PostgreSQL repository")
	}
	readRun := func() (migrationAuditRun0491, error) {
		var r migrationAuditRun0491
		err := auditGet0491(ctx, client, opts.Backend+"/api/v1/admin/migration-runs/"+url.PathEscape(opts.Run), opts.Token, &r)
		return r, err
	}
	run, err := readRun()
	if err != nil {
		return fmt.Errorf("Backend migration read failed: %w", err)
	}
	if run.ID != opts.Run || run.ProjectID != opts.Project || run.SourceKind != "gravit" {
		return errors.New("Backend migration belongs to a different project/source")
	}
	pg, psqlSHA, err := postgresSnapshot0491(ctx, opts)
	if err != nil {
		return err
	}
	if err = matchIntegrationSnapshot0491(opts, run, pg, hostAudit0491{}); err != nil {
		return err
	}
	endpoint := opts.Backend + "/api/v1/admin/extension-hosts/" + url.PathEscape(opts.Extension) + "/probe?scope=" + url.QueryEscape(opts.Scope) + "&scopeId=" + url.QueryEscape(opts.ScopeID)
	probe, err := auditProbe0491(ctx, client, endpoint, opts.Token)
	if err != nil {
		return err
	}
	if err = matchIntegrationSnapshot0491(opts, run, pg, probe.Host); err != nil {
		return err
	}
	if !probe.Java.Responsive || probe.Java.State != "RUNNING" {
		return errors.New("Java JVM did not acknowledge a live RUNNING RPC")
	}
	// Повторно прочитать оба независимых хранилища после выполнения JVM. Параллельная
	// миграция или обновление расширения не должны заверять устаревший межсистемный результат.
	pgAfter, _, err := postgresSnapshot0491(ctx, opts)
	if err != nil {
		return err
	}
	after, err := readRun()
	if err != nil {
		return err
	}
	if pgAfter.Migration == nil || pgAfter.Extension == nil || after != run || *pg.Migration != *pgAfter.Migration || *pg.Extension != *pgAfter.Extension {
		return errors.New("migration or Java install changed during audit")
	}
	if err = matchIntegrationSnapshot0491(opts, after, pgAfter, probe.Host); err != nil {
		return err
	}
	evidence := LiveIntegrationAudit0491{Format: "launcher.live-backend-postgres-java.v1", CheckedAt: time.Now().UTC(), Backend: opts.Backend, BackendVersion: ready.Version,
		ProjectID: opts.Project, MigrationRunID: opts.Run, MigrationRevision: run.Revision, MigrationStatus: run.Status, ExtensionID: opts.Extension, Scope: opts.Scope, ScopeID: opts.ScopeID,
		JavaVersion: probe.Host.Version, JavaInstanceID: probe.Host.InstanceID, JavaGeneration: probe.Host.Generation, PostgreSQLReadOnly: true, PostgreSQLClientSHA256: psqlSHA, Result: "passed"}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	// При ошибке аудита никогда не создавать аттестацию или частичный файл PASS.
	if err = writePrivate(opts.Output, append(data, '\n')); err != nil {
		return err
	}
	fmt.Println("Live Backend/PostgreSQL/Java audit passed; evidence:", opts.Output)
	return nil
}
func matchIntegrationSnapshot0491(opts liveIntegrationOptions0491, run migrationAuditRun0491, pg pgAudit0491, host hostAudit0491) error {
	if pg.Migration == nil || pg.Extension == nil {
		return errors.New("Неполные данные: PostgreSQL migration/extension состояние")
	}
	m, e := pg.Migration, pg.Extension
	if m.ID != run.ID || m.ProjectID != run.ProjectID || m.SourceKind != run.SourceKind || m.Status != run.Status || m.Step != run.Step || m.Revision != run.Revision {
		return errors.New("PostgreSQL migration differs from Backend API")
	}
	if e.ExtensionID != opts.Extension || e.Scope != opts.Scope || e.ScopeID != opts.ScopeID || e.CurrentState != "enabled" || !e.Enabled || e.CurrentVersion == "" || e.Generation < 1 {
		return errors.New("PostgreSQL Java extension is not an enabled install")
	}
	if host.ExtensionID != "" {
		if host.ExtensionID != e.ExtensionID || host.Scope != e.Scope || host.ScopeID != e.ScopeID || host.Generation != e.Generation || host.Version != e.CurrentVersion || host.Runtime != "java-jvm" || host.State != "running" || !host.Healthy || host.InstanceID == "" {
			return errors.New("running Java JVM differs from PostgreSQL installation")
		}
	}
	return nil
}
