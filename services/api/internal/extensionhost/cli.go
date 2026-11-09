package extensionhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionpolicy"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const maxCLIOutput0209 = int64(2 << 20)

type CLIResult0209 struct {
	ExtensionID string `json:"extensionId"`
	Version     string `json:"version"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	ExitCode    int    `json:"exitCode"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	DurationMs  int64  `json:"durationMs"`
	Protocol    string `json:"protocol"`
}

type boundedBuffer0209 struct {
	mu        sync.Mutex
	b         bytes.Buffer
	max       int64
	truncated bool
}

func (b *boundedBuffer0209) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.max - int64(b.b.Len())
	if remaining <= 0 {
		b.truncated = true
		return n, nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.b.Write(p[:remaining])
		b.truncated = true
		return n, nil
	}
	_, _ = b.b.Write(p)
	return n, nil
}
func (b *boundedBuffer0209) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.b.String()
	if b.truncated {
		s += "\n[вывод обрезан Launcher]"
	}
	return s
}

func cliTarget0209(manifest model.ExtensionManifest) (model.ExtensionTarget, error) {
	for _, t := range manifest.Targets {
		if strings.EqualFold(t.Kind, "cli") {
			return t, nil
		}
	}
	return model.ExtensionTarget{}, errors.New("Расширение не объявляет целевую платформу CLI")
}

// RunCLI0209 запускает неизменяемую цель cli как короткоживущий изолированный
// процесс. Он аутентифицируется в том же локальном Extension Host Protocol, что
// расширение бэкенда, и получает возможности только через брокер с запретом по
// умолчанию. Секреты БД, авторизации и хранилища бэкенда ему не передаются.
func (s *Supervisor) RunCLI0209(ctx context.Context, install model.ExtensionInstall, argv []string) (CLIResult0209, error) {
	if install.CurrentState != model.ExtensionInstallStateEnabled || !install.Enabled || install.CurrentVersion == "" {
		return CLIResult0209{}, errors.New("Перед вызовом CLI расширение должно быть включено")
	}
	if len(argv) == 0 || len(argv) > 128 {
		return CLIResult0209{}, errors.New("Для вызова CLI требуется от 1 до 128 аргументов")
	}
	total := 0
	for _, arg := range argv {
		total += len(arg)
		if len(arg) > 16<<10 || strings.ContainsRune(arg, '\x00') {
			return CLIResult0209{}, errors.New("Недопустимый аргумент CLI")
		}
	}
	if total > 128<<10 {
		return CLIResult0209{}, errors.New("Аргументы CLI превышают 128 КиБ")
	}
	ver, err := s.repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return CLIResult0209{}, err
	}
	if err := extensionpolicy.LaunchAllowed(ver.Manifest); err != nil {
		return CLIResult0209{}, err
	}
	target, err := cliTarget0209(ver.Manifest)
	if err != nil {
		return CLIResult0209{}, err
	}
	security := s.securityValue0207()
	if security == nil {
		return CLIResult0209{}, errors.New("Система защиты разрешений расширения недоступна")
	}
	projectID := ""
	if install.Scope == "project" {
		projectID = install.ScopeID
	}
	allowed, err := security.Allowed(ctx, install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, "cli:contribute", projectID)
	if err != nil {
		return CLIResult0209{}, fmt.Errorf("Ошибка загрузки политики разрешений CLI: %w", err)
	}
	if !allowed {
		return CLIResult0209{}, errors.New("Разрешение cli:contribute не предоставлено")
	}
	payloadRoot, err := extensionlifecycle.CurrentPayloadDir(s.cfg.ExtensionRoot, install.Scope, install.ScopeID, install.ExtensionID)
	if err != nil {
		return CLIResult0209{}, err
	}
	entrypoint, err := safeEntrypoint(payloadRoot, target.Entrypoint)
	if err != nil {
		return CLIResult0209{}, err
	}
	token, err := randomHex(32)
	if err != nil {
		return CLIResult0209{}, err
	}
	callbackToken, err := randomHex(32)
	if err != nil {
		return CLIResult0209{}, err
	}
	instance, err := randomHex(16)
	if err != nil {
		return CLIResult0209{}, err
	}
	effective, err := security.Effective(ctx, install.ExtensionID, install.CurrentVersion, install.Scope, install.ScopeID, projectID)
	if err != nil {
		return CLIResult0209{}, err
	}
	permissions := map[string]struct{}{}
	for _, p := range effective {
		permissions[p] = struct{}{}
	}
	st := &processState{key: Key{install.ExtensionID, install.Scope, install.ScopeID}.normalized(), install: install, manifest: ver.Manifest, permissions: permissions, token: token, callbackToken: callbackToken, instanceID: instance, entrypoint: target.Entrypoint, state: "starting", javaHost: sameHostJar0304(entrypoint), helloCh: make(chan struct{}), readyCh: make(chan struct{}), doneCh: make(chan struct{}), logs: ringLog{maxBytes: s.cfg.MaxLogBytes, maxEntries: s.cfg.MaxLogEntries}}
	// Снимок разрешений выше предназначен только для отчёта. Ни старое поколение
	// установки, ни отозванный грант CLI не должны разрешать exec.
	if err := s.enforceCLITrust04312(ctx, st); err != nil {
		return CLIResult0209{}, fmt.Errorf("Доверие к CLI-расширению отклонено: %w", err)
	}
	s.mu.RLock()
	baseURL := s.baseURL
	s.mu.RUnlock()
	if baseURL == "" {
		return CLIResult0209{}, errors.New("Сервер протокола хоста расширений не запущен")
	}
	if err := s.registerTransient0209(st); err != nil {
		return CLIResult0209{}, err
	}
	defer s.removeProcessToken(st)
	var cmd *exec.Cmd
	if sameHostJar0304(entrypoint) {
		cmd, err = s.javaCommand0304(entrypoint, argv)
		if err != nil {
			return CLIResult0209{}, err
		}
	} else {
		cmd = exec.Command(entrypoint, argv...)
	}
	cmd.Dir = payloadRoot
	cmd.Env = sanitizedEnvironment(map[string]string{
		"LAUNCHER_EXTENSION_HOST_URL": baseURL, "LAUNCHER_EXTENSION_HOST_TOKEN": token, "LAUNCHER_EXTENSION_CALLBACK_TOKEN": callbackToken, "LAUNCHER_EXTENSION_HOST_PROTOCOL": ProtocolVersion, "LAUNCHER_EXTENSION_API_VERSION": extensioncontract.ExtensionAPIVersion, "LAUNCHER_EXTENSION_INSTANCE_ID": instance,
		"LAUNCHER_EXTENSION_ID": install.ExtensionID, "LAUNCHER_EXTENSION_VERSION": install.CurrentVersion, "LAUNCHER_EXTENSION_SCOPE": install.Scope, "LAUNCHER_EXTENSION_SCOPE_ID": install.ScopeID, "LAUNCHER_EXTENSION_TARGET": "cli",
	})
	if st.javaHost {
		scratch, err := prepareJavaScratch04811(cmd)
		if err != nil {
			return CLIResult0209{}, err
		}
		defer os.RemoveAll(scratch)
	}
	var isolatedHandle *extensionSandbox03111
	if ver.Manifest.Sandbox != nil && ver.Manifest.Sandbox.Mode == "isolated" {
		if st.javaHost {
			return CLIResult0209{}, errors.New("sandbox-unavailable: для обратных вызовов Java требуется аутентифицированный обратный RPC")
		}
		if err := s.validateSharedRoots03110(ver.Manifest.Sandbox); err != nil {
			return CLIResult0209{}, err
		}
		isolatedHandle, err = prepareExtensionSandbox03111(payloadRoot, entrypoint, cmd, baseURL, s.server.Handler, ver.Manifest.Sandbox)
		if err != nil {
			return CLIResult0209{}, fmt.Errorf("sandbox-unavailable: %w", err)
		}
		defer isolatedHandle.Close()
		cmd = isolatedHandle.Cmd
		st.mu.Lock()
		st.sandbox = isolatedHandle
		st.mu.Unlock()
	} else {
		configureProcess(cmd)
	}

	stdout := &boundedBuffer0209{max: maxCLIOutput0209}
	stderr := &boundedBuffer0209{max: maxCLIOutput0209}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if ver.Manifest.Sandbox != nil && ver.Manifest.Sandbox.Mode == "isolated" {
		// Общая квота покрывает оба потока и ответы Host Protocol.
		var outputBreach sync.Once
		abort := func() {
			if cmd.Process != nil {
				_ = killProcessTree(cmd.Process)
			}
		}
		cmd.Stdout = &cliOutputWriter03113{st: st, target: stdout, policy: ver.Manifest.Sandbox, abort: abort, once: &outputBreach}
		cmd.Stderr = &cliOutputWriter03113{st: st, target: stderr, policy: ver.Manifest.Sandbox, abort: abort, once: &outputBreach}
	}
	// Повторно проверяйте устойчивые полномочия после подготовки пакета/песочницы.
	// Экстренное отключение, отзыв ключа издателя или удаление разрешения в это окно
	// должны предотвратить исполнение, даже если первоначальный снимок прошёл.
	if err := s.enforceCLITrust04312(ctx, st); err != nil {
		return CLIResult0209{}, fmt.Errorf("Доверие к CLI-расширению изменилось перед запуском: %w", err)
	}
	st.mu.Lock()
	stopRequestedBeforeExec := st.expectedStop
	st.mu.Unlock()
	if stopRequestedBeforeExec {
		return CLIResult0209{}, errors.New("CLI-расширение остановлено перед запуском")
	}
	started := time.Now().UTC()
	if err := cmd.Start(); err != nil {
		return CLIResult0209{}, fmt.Errorf("Ошибка запуска CLI-расширения: %w", err)
	}
	if isolatedHandle != nil {
		if err := isolatedHandle.Started(); err != nil {
			return CLIResult0209{}, fmt.Errorf("Не удалось применить политику изоляции: %w", err)
		}
	}
	st.mu.Lock()
	st.cmd = cmd
	st.startedAt = started
	st.processCount = 1
	st.sandboxReady = isolatedHandle != nil
	stopRequested := st.expectedStop
	st.mu.Unlock()
	if stopRequested {
		_ = killProcessTree(cmd.Process)
	}
	waitCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		close(st.doneCh)
		waitCh <- err
	}()
	startup := time.NewTimer(s.cfg.StartupTimeout)
	defer startup.Stop()
	select {
	case <-st.helloCh:
	case waitErr := <-waitCh:
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		result := CLIResult0209{ExtensionID: install.ExtensionID, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, ExitCode: code, Stdout: redactHostCredentials04811(stdout.String(), st.token, st.callbackToken), Stderr: redactHostCredentials04811(stderr.String(), st.token, st.callbackToken), DurationMs: time.Since(started).Milliseconds(), Protocol: ProtocolVersion}
		if waitErr != nil {
			return result, fmt.Errorf("CLI-расширение завершилось до аутентифицированного hello: %w", waitErr)
		}
		return result, errors.New("CLI-расширение завершилось до аутентифицированного hello")
	case <-startup.C:
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, fmt.Errorf("Время ожидания hello CLI-расширения истекло через %s", s.cfg.StartupTimeout)
	case <-ctx.Done():
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, ctx.Err()
	case <-s.ctx.Done():
		_ = killProcessTree(cmd.Process)
		return CLIResult0209{}, errors.New("Хост расширений завершает работу")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-waitCh:
			// Краткоживущая команда может закончиться между проверками монитора. Не
			// сообщайте об успешном исполнении после отзыва полномочий.
			if err := s.enforceCLITrust04312(ctx, st); err != nil {
				return CLIResult0209{}, fmt.Errorf("Полномочия CLI-расширения отозваны: %w", err)
			}
			st.mu.Lock()
			terminated := st.expectedStop || st.terminationInitiated
			st.mu.Unlock()
			if terminated {
				return CLIResult0209{}, errors.New("CLI-расширение завершено контроллером")
			}
			code := 0
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			}
			result := CLIResult0209{ExtensionID: install.ExtensionID, Version: install.CurrentVersion, Scope: install.Scope, ScopeID: install.ScopeID, ExitCode: code, Stdout: redactHostCredentials04811(stdout.String(), st.token, st.callbackToken), Stderr: redactHostCredentials04811(stderr.String(), st.token, st.callbackToken), DurationMs: time.Since(started).Milliseconds(), Protocol: ProtocolVersion}
			if waitErr != nil || code != 0 {
				return result, fmt.Errorf("CLI-расширение завершилось с кодом %d", code)
			}
			return result, nil
		case <-ticker.C:
			// Не полагайтесь на глобальный монитор с интервалом 1 секунду: проверяйте
			// текущие разрешения и поколение установки во время исполнения кода CLI.
			if err := s.enforceCLITrust04312(ctx, st); err != nil {
				_ = killProcessTree(cmd.Process)
				return CLIResult0209{}, fmt.Errorf("Полномочия CLI-расширения отозваны: %w", err)
			}
			if cmd.Process != nil {
				if rss, count, e := processTreeUsage(cmd.Process.Pid); e == nil {
					if s.cfg.MaxMemoryBytes > 0 && rss > s.cfg.MaxMemoryBytes {
						_ = killProcessTree(cmd.Process)
						return CLIResult0209{}, fmt.Errorf("CLI-расширение превысило лимит памяти: %d > %d", rss, s.cfg.MaxMemoryBytes)
					}
					if s.cfg.MaxProcesses > 0 && count > s.cfg.MaxProcesses {
						_ = killProcessTree(cmd.Process)
						return CLIResult0209{}, fmt.Errorf("CLI-расширение превысило лимит процессов: %d > %d", count, s.cfg.MaxProcesses)
					}
				}
			}
		case <-ctx.Done():
			_ = terminateProcessTree(cmd.Process)
			select {
			case <-waitCh:
			case <-time.After(s.cfg.StopTimeout):
				_ = killProcessTree(cmd.Process)
			}
			return CLIResult0209{}, ctx.Err()
		case <-s.ctx.Done():
			_ = terminateProcessTree(cmd.Process)
			select {
			case <-waitCh:
			case <-time.After(s.cfg.StopTimeout):
				_ = killProcessTree(cmd.Process)
			}
			return CLIResult0209{}, errors.New("Хост расширений завершает работу")
		}
	}
}
