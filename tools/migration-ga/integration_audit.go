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
// Он сверяет запись действующей PostgreSQL, авторизованный Go API и *реальный
// RPC-ответ* установленного Java Host. Одного успешного API /ready или
// кешированного сигнала диспетчера недостаточно. SQL-транзакция доступна
// только для чтения, в том числе в производственной среде.
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
	backend := fs.String("backend", "", "HTTPS-адрес серверной части (или HTTP для числового адреса петлевого интерфейса)")
	project := fs.String("project", "", "Идентификатор существующего проекта")
	run := fs.String("run", "", "Идентификатор существующего запуска миграции Gravit")
	extension := fs.String("extension", "", "Идентификатор установленного и запущенного расширения хоста Java")
	scope := fs.String("scope", "global", "Глобальная область или проект")
	scopeID := fs.String("scope-id", "", "Идентификатор проекта для расширения с областью действия проекта")
	dsnEnv := fs.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Переменная окружения с DSN PostgreSQL")
	psql := fs.String("psql", "psql", "Путь к исполняемому файлу psql")
	output := fs.String("output", "", "Новый конфиденциальный JSON-файл свидетельств")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" || !validEnvironmentName0491(*dsnEnv) {
		return errors.New("Требуются --output и --dsn-env; дополнительные аргументы запрещены")
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

// psql запускается без оболочки и DSN в аргументах. libpq получает DSN через
// PGDATABASE. SQL содержит только запросы чтения и безопасно экранированные
// идентификаторы, без изменений схемы, временных таблиц и прав записи.
func postgresSnapshot0491(ctx context.Context, opts liveIntegrationOptions0491) (pgAudit0491, string, error) {
	var record pgAudit0491
	exe, err := exec.LookPath(opts.PSQL)
	if err != nil {
		return record, "", fmt.Errorf("Отсутствует: исполняемый файл psql: %w", err)
	}
	executableSHA, err := shaFile(exe, 256<<20)
	if err != nil {
		return record, "", fmt.Errorf("Не удалось проверить исполняемый файл psql: %w", err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	sql := `BEGIN READ ONLY;\nSELECT json_build_object(\n` +
		`'readOnly',current_setting('transaction_read_only'),` +
		`'project',(SELECT id FROM projects WHERE id=` + quote(opts.Project) + `),` +
		`'migration',(SELECT row_to_json(m) FROM (SELECT id,project_id,source_kind,status,step,revision FROM migration_runs_0331 WHERE id=` + quote(opts.Run) + `) m),` +
		`'extension',(SELECT row_to_json(e) FROM (SELECT extension_id,scope,scope_id,current_version,current_state,generation,enabled FROM extension_installs WHERE extension_id=` + quote(opts.Extension) + ` AND scope=` + quote(opts.Scope) + ` AND scope_id=` + quote(opts.ScopeID) + `) e)` +
		`)::text;\nCOMMIT;\n`
	// Настоящие переводы строк, а не экранированные строковые литералы SQL.
	sql = strings.ReplaceAll(sql, `\n`, "\n")
	cmd := exec.CommandContext(ctx, exe, "--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Env = append(withoutPostgresEnvironment0491(os.Environ(), opts), "PGDATABASE="+opts.DSN, "PGCONNECT_TIMEOUT=7", "PGOPTIONS=-c default_transaction_read_only=on")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return record, "", fmt.Errorf("Ошибка транзакции PostgreSQL только для чтения (код завершения psql: %v)", err)
	} // redact stderr: may include DSN
	if stdout.Len() > 16<<10 {
		return record, "", errors.New("Превышен допустимый размер: ответ аудита PostgreSQL")
	}
	if err = json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &record); err != nil {
		return record, "", errors.New("Некорректное значение: JSON, прочитанный из PostgreSQL")
	}
	if record.ReadOnly != "on" || record.Project != opts.Project || record.Migration == nil || record.Extension == nil {
		return record, "", errors.New("В PostgreSQL отсутствуют проект, миграция или расширение либо транзакция не ограничена чтением")
	}
	return record, executableSHA, nil
}
func withoutPostgresEnvironment0491(env []string, opts liveIntegrationOptions0491) []string {
	out := make([]string, 0, len(env))
	for _, v := range env {
		key, value, _ := strings.Cut(v, "=")
		// Не передавайте токен авторизации API или дополнительную копию учётных данных
		// PostgreSQL внешнему клиентскому процессу.
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
	// Текущие ответы Backend содержат дополнительные версионированные поля.
	// Сохраните проверку оболочки ответа и декодируйте только известные поля аудита.
	var raw json.RawMessage
	if err := getJSON(ctx, client, endpoint, token, &raw); err != nil {
		return err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("Пустое значение: представление данных на сервере")
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
		return result, fmt.Errorf("Ошибка: запрос проверочного запуска Java: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return result, fmt.Errorf("Проверка работающей Java вернула отказ HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil {
		return result, err
	}
	if len(data) > 64<<10 {
		return result, errors.New("Ответ проверки Java превышает допустимый размер")
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal(data, &envelope); err != nil {
		return result, err
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return result, errors.New("Отсутствует: данные проверочного запуска Java")
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
			return errors.New("Некорректный идентификатор проекта, запуска или расширения")
		}
	}
	if !validAuditScope0491(opts.Scope, opts.ScopeID, opts.Project) || opts.DSN == "" || opts.Token == "" {
		return errors.New("Некорректная область действия, DSN PostgreSQL или токен администратора")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Готовность Backend должна учитывать реальный отклик PostgreSQL и состояние схемы.
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
		return fmt.Errorf("Ошибка проверки готовности серверной части: %w", err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return fmt.Errorf("Серверная часть не готова: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<10+1))
	res.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > 16<<10 || json.Unmarshal(body, &ready) != nil || ready.Status != "ready" || ready.Repository != "postgres" || ready.Checks["repository"] != "ok" || ready.Checks["migrations"] == "" {
		return errors.New("Серверная часть не подтверждает наличие работающего перенесённого репозитория PostgreSQL")
	}
	readRun := func() (migrationAuditRun0491, error) {
		var r migrationAuditRun0491
		err := auditGet0491(ctx, client, opts.Backend+"/api/v1/admin/migration-runs/"+url.PathEscape(opts.Run), opts.Token, &r)
		return r, err
	}
	run, err := readRun()
	if err != nil {
		return fmt.Errorf("Ошибка чтения состояния миграции серверной части: %w", err)
	}
	if run.ID != opts.Run || run.ProjectID != opts.Project || run.SourceKind != "gravit" {
		return errors.New("Миграция серверной части относится к другому проекту или источнику")
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
		return errors.New("JVM Java не подтвердила работающий RPC в состоянии RUNNING")
	}
	// После выполнения JVM повторно прочитайте оба независимых хранилища.
	// Параллельная миграция или обновление расширения не должны заверять устаревший результат сверки систем.
	pgAfter, _, err := postgresSnapshot0491(ctx, opts)
	if err != nil {
		return err
	}
	after, err := readRun()
	if err != nil {
		return err
	}
	if pgAfter.Migration == nil || pgAfter.Extension == nil || after != run || *pg.Migration != *pgAfter.Migration || *pg.Extension != *pgAfter.Extension {
		return errors.New("Миграция или установка Java изменились во время проверки")
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
	// Неуспешный аудит никогда не создаёт аттестацию или частичный файл PASS.
	if err = writePrivate(opts.Output, append(data, '\n')); err != nil {
		return err
	}
	fmt.Println("Проверка работающих Backend, PostgreSQL и Java пройдена; доказательные данные:", opts.Output)
	return nil
}
func matchIntegrationSnapshot0491(opts liveIntegrationOptions0491, run migrationAuditRun0491, pg pgAudit0491, host hostAudit0491) error {
	if pg.Migration == nil || pg.Extension == nil {
		return errors.New("Неполное состояние миграции или расширения PostgreSQL")
	}
	m, e := pg.Migration, pg.Extension
	if m.ID != run.ID || m.ProjectID != run.ProjectID || m.SourceKind != run.SourceKind || m.Status != run.Status || m.Step != run.Step || m.Revision != run.Revision {
		return errors.New("Миграция PostgreSQL не совпадает с данными API серверной части")
	}
	if e.ExtensionID != opts.Extension || e.Scope != opts.Scope || e.ScopeID != opts.ScopeID || e.CurrentState != "enabled" || !e.Enabled || e.CurrentVersion == "" || e.Generation < 1 {
		return errors.New("Расширение Java в PostgreSQL не является активной установкой")
	}
	if host.ExtensionID != "" {
		if host.ExtensionID != e.ExtensionID || host.Scope != e.Scope || host.ScopeID != e.ScopeID || host.Generation != e.Generation || host.Version != e.CurrentVersion || host.Runtime != "java-jvm" || host.State != "running" || !host.Healthy || host.InstanceID == "" {
			return errors.New("Работающая JVM Java отличается от установки, зарегистрированной в PostgreSQL")
		}
	}
	return nil
}
