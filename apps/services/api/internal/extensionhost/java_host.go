package extensionhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionjava"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const javaRPCVersion0304 = "1.0"

// Все проверки JAR общие с предварительной проверкой жизненного цикла (0.30.5).
// Не ослабляйте их, когда оператор запускает JAR в обход установщика.
func validateJavaJar0304(path string) error {
	_, err := extensionjava.Inspect(path)
	return err
}

// javaCommand0304 находит доверенный исполняемый файл Java и не принимает аргументы команды из пакета.
func (s *Supervisor) javaCommand0304(jar string, argv []string) (*exec.Cmd, error) {
	java := strings.TrimSpace(s.cfg.JavaExecutable)
	if java != "" {
		if !filepath.IsAbs(java) {
			return nil, errors.New("Путь к настроенному исполняемому файлу Java должен быть абсолютным")
		}
		info, err := os.Lstat(java)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Настроенный исполняемый файл Java должен быть обычным файлом, а не символической ссылкой")
		}
	} else {
		var err error
		java, err = exec.LookPath("java")
		if err != nil {
			return nil, fmt.Errorf("Отсутствует среда выполнения Java 17+: %w", err)
		}
		// Процесс никогда не должен получать исполняемый файл из неявного элемента PATH,
		// указывающего на рабочий каталог. Разрешайте обычную ссылку alternatives для JDK.
		java, err = filepath.EvalSymlinks(java)
		if err != nil {
			return nil, fmt.Errorf("Ошибка определения среды выполнения Java: %w", err)
		}
	}
	if !filepath.IsAbs(java) {
		return nil, errors.New("Путь к найденному исполняемому файлу Java должен быть абсолютным")
	}
	info, err := os.Stat(java)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return nil, errors.New("Исполняемый файл Java должен быть обычным исполняемым файлом")
	}
	// Это ограничения памяти JVM, а не изоляция ОС: монитор дерева процессов
	// остаётся границей контроля общего RSS. Оставляйте нативный запас для
	// потоков, GC, JIT и libc вместо выделения 65 % памяти только куче Java.
	memoryMiB := s.cfg.MaxMemoryBytes / (1 << 20)
	if memoryMiB < 256 {
		return nil, errors.New("Для Java Host требуется не менее 256 МиБ памяти процесса")
	}
	javaHeap := minInt64_04811(memoryMiB*40/100, 4096)
	javaMeta := minInt64_04811(memoryMiB*20/100, 512)
	javaDirect := minInt64_04811(memoryMiB*10/100, 256)
	javaCode := minInt64_04811(memoryMiB*10/100, 256)
	args := []string{
		"-XX:+ExitOnOutOfMemoryError", "-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash",
		"-Djava.awt.headless=true", "-Dfile.encoding=UTF-8", "-Djdk.attach.allowAttachSelf=false",
		fmt.Sprintf("-Xmx%dm", javaHeap),
		fmt.Sprintf("-XX:MaxMetaspaceSize=%dm", javaMeta),
		fmt.Sprintf("-XX:MaxDirectMemorySize=%dm", javaDirect),
		fmt.Sprintf("-XX:ReservedCodeCacheSize=%dm", javaCode), "-jar", jar,
	}
	args = append(args, argv...)
	return exec.Command(java, args...), nil
}

type javaRPCRequest0304 struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
	DeadlineMs      int64           `json:"deadlineMs"`
}
type javaRPCResponse0304 struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	OK              bool            `json:"ok"`
	Result          json.RawMessage `json:"result"`
}

// CallJavaRPC0304 выполняет аутентифицированный запрос Go → JVM с крайним сроком.
// Он доступен только для работающего Java-процесса, зарегистрированного руководителем.
func (s *Supervisor) CallJavaRPC0304(ctx context.Context, key Key, method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "health", "command.invoke", "event.deliver", "hook.deliver", "auth.health", "auth.password", "auth.resolve", "auth.session.verify", "auth.session.revoke", "content.health", "content.source.resolve", "content.texture.resolve", "content.delivery.resolve", "content.metadata.enrich", "content.package.prepare", "ui.action.invoke", "ui.settings.get", "ui.settings.put", "state.migrate":
	default:
		return nil, errors.New("Неподдерживаемый метод Java RPC")
	}
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if len(params) > 64<<10 || !json.Valid(params) || params[0] != '{' {
		return nil, errors.New("Параметры Java RPC должны быть объектом JSON ограниченного размера")
	}
	key = key.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return nil, ErrHostNotRunning
	}
	st.mu.Lock()
	running := st.state == "running" && st.javaHost
	endpoint, token := st.callbackURL, st.callbackToken
	st.mu.Unlock()
	if !running || endpoint == "" {
		return nil, ErrHostNotRunning
	}
	if strings.HasPrefix(method, "auth.") {
		// Коннекторы авторизации разрешены только явно согласованным
		// глобальным установкам. Расширения проекта не могут авторизовать аккаунты.
		if key.Scope != "global" || st.manifest.ID != key.ExtensionID {
			return nil, errors.New("Доступ к области провайдера авторизации Java запрещён")
		}
		declared := false
		for _, permission := range st.manifest.Permissions {
			if permission == "auth:provider" {
				declared = true
				break
			}
		}
		if !declared {
			return nil, errors.New("Разрешение авторизации Java не объявлено")
		}
		allowed, err := s.permissionAllowed0207(ctx, st, "auth:provider", "")
		if err != nil || !allowed {
			return nil, errors.New("Разрешение авторизации Java отозвано или недоступно")
		}
	}
	if strings.HasPrefix(method, "content.") {
		// Обратные вызовы контента не могут выпускать подписанные релизы или обходить брокер Go.
		// Глобальному расширению необходимо разрешение release:read для явного проекта;
		// расширение проекта ограничено проектом своей установки.
		var payload struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(params, &payload); err != nil {
			return nil, errors.New("Недопустимый проект содержимого")
		}
		if method != "content.health" {
			id, err := s.scopedProject(st, payload.ProjectID)
			if err != nil {
				return nil, errors.New("Доступ к области проекта содержимого запрещён")
			}
			permission := "release:read"
			if method == "content.package.prepare" {
				permission = "release:prepare"
			}
			granted, err := s.permissionAllowed0207(ctx, st, permission, id)
			if err != nil || !granted {
				return nil, errors.New("Разрешение на содержимое отклонено или недоступно")
			}
		}
	}
	// Обратные вызовы интерфейса доступны только подписанным дополнениям Admin/Desktop.
	// Никогда не принимайте произвольные имена Java-методов и обработчиков из iframe.
	if strings.HasPrefix(method, "ui.") {
		if err := s.checkJavaUI0489(ctx, st, method, params); err != nil {
			return nil, err
		}
	}
	// Ранее разрешённая команда супервизора не должна конкурировать с аварийным
	// отключением, отзывом издателя или заменённой установкой. HTTP-брокер
	// проверяет актуальное доверие, но прямой RPC Go → JVM обходит его.
	if err := s.enforceLiveTrust04210(ctx, st); err != nil {
		s.denyRevokedHost04210(st, err)
		return nil, fmt.Errorf("Java RPC отклонён текущей политикой доверия расширения: %w", err)
	}
	// Процесс может быть остановлен или заменён во время длительной проверки.
	st.mu.Lock()
	stillRunning := st.state == "running" && st.javaHost && st.callbackURL == endpoint && st.callbackToken == token
	st.mu.Unlock()
	if !stillRunning {
		return nil, ErrHostNotRunning
	}
	result, err := s.callJavaProcess0304(ctx, endpoint, token, method, params)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(method, "auth.") {
		allowed, checkErr := s.permissionAllowed0207(ctx, st, "auth:provider", "")
		if checkErr != nil || !allowed {
			return nil, errors.New("Разрешение авторизации Java отозвано во время операции")
		}
	}
	if strings.HasPrefix(method, "content.") && method != "content.health" {
		var payload struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(params, &payload); err != nil {
			return nil, errors.New("Недопустимая область действия содержимого")
		}
		id, err := s.scopedProject(st, payload.ProjectID)
		if err != nil {
			return nil, err
		}
		permission := "release:read"
		if method == "content.package.prepare" {
			permission = "release:prepare"
		}
		granted, err := s.permissionAllowed0207(ctx, st, permission, id)
		if err != nil || !granted {
			return nil, errors.New("Разрешение на содержимое отозвано во время RPC")
		}
	}
	if strings.HasPrefix(method, "ui.") {
		if err := s.checkJavaUI0489(ctx, st, method, params); err != nil {
			return nil, fmt.Errorf("Разрешение интерфейса Java отозвано во время RPC: %w", err)
		}
	}
	if method == "state.migrate" {
		if err := s.enforceLiveTrust04210(ctx, st); err != nil {
			return nil, fmt.Errorf("Доверие к миграции состояния Java отозвано: %w", err)
		}
	}
	return result, nil
}
func (s *Supervisor) callJavaProcess0304(ctx context.Context, endpoint, token, method string, params json.RawMessage) (json.RawMessage, error) {
	budget := s.cfg.CapabilityTimeout
	if method == "state.migrate" {
		// Миграции состояния ограничиваются отдельно от обычных интерактивных RPC;
		// общий тайм-аут HTTP-обратного вызова по умолчанию составляет 10 секунд.
		budget = 8 * time.Second
	} else {
		if budget > 1800*time.Millisecond {
			budget = 1800 * time.Millisecond
		}
		if budget <= 0 {
			budget = 1800 * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	id, err := randomHex(12)
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(javaRPCRequest0304{ProtocolVersion: javaRPCVersion0304, RequestID: id, Method: method, Params: params, DeadlineMs: int64(budget.Milliseconds())})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/rpc", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.callbackClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Ошибка Java RPC %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(body) > 65536 {
		return nil, errors.New("Ответ Java RPC превышает 64 КиБ")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Java RPC %s вернул HTTP %d", method, resp.StatusCode)
	}
	var answer javaRPCResponse0304
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&answer); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Лишние данные после ответа Java RPC")
	}
	if !answer.OK || answer.ProtocolVersion != javaRPCVersion0304 || answer.RequestID != id || !json.Valid(answer.Result) {
		return nil, errors.New("Несовпадение протокола Java RPC или идентификатора запроса")
	}
	return answer.Result, nil
}

// probeJava0304 работает независимо от монитора heartbeat и ресурсов супервизора.
// Некорректный обратный вызов может продолжать слать heartbeat, но не оставит зависшую JVM живой.
func (s *Supervisor) probeJava0304(st *processState) {
	defer func() { st.mu.Lock(); st.rpcBusy = false; st.mu.Unlock() }()
	st.mu.Lock()
	endpoint, token := st.callbackURL, st.callbackToken
	st.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.CapabilityTimeout)
	defer cancel()
	payload, err := s.callJavaProcess0304(ctx, endpoint, token, "health", json.RawMessage(`{}`))
	if err == nil {
		var result struct {
			State      string `json:"state"`
			Responsive bool   `json:"responsive"`
		}
		if e := json.Unmarshal(payload, &result); e != nil || !result.Responsive || result.State != "RUNNING" {
			err = errors.New("Хост Java не находится в состоянии RUNNING")
		}
	}
	st.mu.Lock()
	if st.state != "running" {
		st.mu.Unlock()
		return
	}
	if err == nil {
		st.rpcFailures = 0
		st.mu.Unlock()
		return
	}
	st.rpcFailures++
	failures := st.rpcFailures
	st.mu.Unlock()
	s.addLog(st, "host", "warn", fmt.Sprintf("Java RPC liveness probe failed (%d/3): %v", failures, err), nil)
	if failures >= 3 {
		s.failProcess(st, "Java RPC unresponsive after 3 probes", false)
	}
}

// Проверка уровня пакета сохраняет независимость Java JAR-верификатора от запуска
// процессов ОС.
func sameHostJar0304(path string) bool { return strings.EqualFold(filepath.Ext(path), ".jar") }

// MigrateExtensionState04810 вызывает зарегистрированный граф миграций новой уже
// аутентифицированной JVM. Менеджер обновлений управляет устойчивыми контрольными
// точками, перезапусками и компенсациями; метод никогда не обходит живое доверие и
// разрешения.
func (s *Supervisor) MigrateExtensionState04810(ctx context.Context, install model.ExtensionInstall, fromVersion string) error {
	if fromVersion == "" || fromVersion == install.CurrentVersion {
		return nil
	}
	// Расширения вне Java не имеют Java-обратных вызовов. Их состояние без
	// изменений сохраняет тот же путь устойчивых контрольных точек и отката.
	version, err := s.repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return err
	}
	target, err := backendTarget(version.Manifest)
	if errors.Is(err, ErrNoBackendTarget) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = target
	key := Key{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID}.normalized()
	s.mu.RLock()
	st := s.processes[key.String()]
	s.mu.RUnlock()
	if st == nil {
		return ErrHostNotRunning
	}
	st.mu.Lock()
	java := st.javaHost
	sameVersion := st.install.CurrentVersion == install.CurrentVersion && st.install.Generation == install.Generation && st.install.CurrentPackageIdentity == install.CurrentPackageIdentity
	st.mu.Unlock()
	if !sameVersion {
		return errors.New("Поколение расширения изменилось во время миграции состояния")
	}
	if !java {
		return nil
	}
	params, err := json.Marshal(map[string]string{"fromVersion": fromVersion, "toVersion": install.CurrentVersion})
	if err != nil {
		return err
	}
	body, err := s.CallJavaRPC0304(ctx, key, "state.migrate", params)
	if err != nil {
		return fmt.Errorf("Ошибка обратного вызова миграции состояния: %w", err)
	}
	var answer struct {
		FromVersion string `json:"fromVersion"`
		ToVersion   string `json:"toVersion"`
		Applied     bool   `json:"applied"`
	}
	if err = json.Unmarshal(body, &answer); err != nil {
		return err
	}
	if answer.FromVersion != fromVersion || answer.ToVersion != install.CurrentVersion {
		return errors.New("Недопустимое подтверждение миграции")
	}
	return nil
}

// Сохраняйте арифметику независимой от универсального min в Go и minInt пакета.
func minInt64_04811(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
