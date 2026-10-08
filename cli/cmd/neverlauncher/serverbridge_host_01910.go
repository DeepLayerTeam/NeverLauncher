package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const serverBridgeHostStateDir01910 = ".neverlauncher/server-bridge/host"

type serverBridgeHostConfig01910 struct {
	SchemaVersion        string   `json:"schemaVersion"`
	ProductVersion       string   `json:"productVersion"`
	ServerRoot           string   `json:"serverRoot"`
	Platform             string   `json:"platform"`
	LaunchMode           string   `json:"launchMode"`
	JavaPath             string   `json:"javaPath"`
	JavaMajor            int      `json:"javaMajor"`
	ServerJar            string   `json:"serverJar,omitempty"`
	JavaArgsFile         string   `json:"javaArgsFile,omitempty"`
	JVMArgs              []string `json:"jvmArgs,omitempty"`
	ServerArgs           []string `json:"serverArgs,omitempty"`
	RestartPolicy        string   `json:"restartPolicy"`
	MaxRestarts          int      `json:"maxRestarts"`
	RestartBackoffMillis int      `json:"restartBackoffMillis"`
	StopTimeoutSeconds   int      `json:"stopTimeoutSeconds"`
	CreatedAt            string   `json:"createdAt"`
	UpdatedAt            string   `json:"updatedAt"`
}

type serverBridgeHostRuntime01910 struct {
	SchemaVersion string   `json:"schemaVersion"`
	SessionID     string   `json:"sessionId"`
	Status        string   `json:"status"`
	Platform      string   `json:"platform"`
	SupervisorPID int      `json:"supervisorPid"`
	ProcessPID    int      `json:"processPid"`
	JavaPath      string   `json:"javaPath"`
	JavaMajor     int      `json:"javaMajor"`
	Command       []string `json:"command"`
	StartedAt     string   `json:"startedAt"`
	ProcessAt     string   `json:"processStartedAt,omitempty"`
	LastExitAt    string   `json:"lastExitAt,omitempty"`
	ExitCode      *int     `json:"exitCode,omitempty"`
	Crashed       bool     `json:"crashed"`
	RestartCount  int      `json:"restartCount"`
	CrashCount    int      `json:"crashCount"`
	LastCrashAt   string   `json:"lastCrashAt,omitempty"`
	LastError     string   `json:"lastError,omitempty"`
}

type serverBridgeHostLock01910 struct {
	SchemaVersion string `json:"schemaVersion"`
	PID           int    `json:"pid"`
	SessionID     string `json:"sessionId"`
	CreatedAt     string `json:"createdAt"`
}

type hostCombinedWriter01910 struct {
	mu sync.Mutex
	w  io.Writer
}

type hostStreamWriter01910 struct {
	raw           io.Writer
	combined      *hostCombinedWriter01910
	label         string
	console       bool
	consoleWriter io.Writer
}

func (w *hostStreamWriter01910) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := w.raw.Write(p); err != nil {
		return 0, err
	}
	if w.console && w.consoleWriter != nil {
		_, _ = w.consoleWriter.Write(p)
	}
	w.combined.mu.Lock()
	_, combinedErr := fmt.Fprintf(w.combined.w, "%s [%s] %s", time.Now().UTC().Format(time.RFC3339Nano), w.label, string(p))
	if len(p) > 0 && p[len(p)-1] != '\n' {
		_, _ = io.WriteString(w.combined.w, "\n")
	}
	w.combined.mu.Unlock()
	if combinedErr != nil {
		return 0, combinedErr
	}
	return len(p), nil
}

func handleServerBridgeHost01910(args []string) error {
	if len(args) == 0 {
		return errors.New("использование: nl сервер-мост хост настраивать|запуск|запуск|остановка|перезапуск|состояние|журналы [параметры]")
	}
	switch args[0] {
	case "configure":
		return configureServerBridgeHost01910(args[1:])
	case "start":
		return startServerBridgeHost01910(args[1:])
	case "run":
		return runServerBridgeHostCommand01910(args[1:])
	case "stop":
		return stopServerBridgeHost01910(args[1:])
	case "restart":
		return restartServerBridgeHost01910(args[1:])
	case "status":
		return statusServerBridgeHost01910(args[1:])
	case "logs":
		return logsServerBridgeHost01910(args[1:])
	default:
		return fmt.Errorf("неизвестная сервер-мост хост подкоманда: %s", args[0])
	}
}

func hostPaths01910(root string) map[string]string {
	dir := filepath.Join(root, filepath.FromSlash(serverBridgeHostStateDir01910))
	return map[string]string{
		"dir":        dir,
		"config":     filepath.Join(dir, "host.json"),
		"runtime":    filepath.Join(dir, "runtime.json"),
		"lock":       filepath.Join(dir, "host.lock"),
		"stop":       filepath.Join(dir, "stop.request"),
		"stdout":     filepath.Join(dir, "stdout.log"),
		"stderr":     filepath.Join(dir, "stderr.log"),
		"combined":   filepath.Join(dir, "server.log"),
		"supervisor": filepath.Join(dir, "supervisor.log"),
	}
}

func configureServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	detection, err := detectServerBridgePlatform0199(root, flagValue(args, "--platform", ""))
	if err != nil {
		return err
	}
	javaPath, javaMajor, err := resolveServerBridgeHostJava01910(flagValue(args, "--java", ""))
	if err != nil {
		return err
	}
	launchMode := strings.ToLower(strings.TrimSpace(flagValue(args, "--launch-mode", "")))
	serverJar := strings.TrimSpace(flagValue(args, "--server-jar", ""))
	javaArgsFile := strings.TrimSpace(flagValue(args, "--java-args-file", ""))
	if launchMode == "" {
		if javaArgsFile != "" {
			launchMode = "java-args-file"
		} else if detection.Platform == "forge" || detection.Platform == "neoforge" {
			if argsFile := detectModernForgeArgsFile01910(root, detection.Platform); argsFile != "" {
				launchMode = "java-args-file"
				javaArgsFile = argsFile
			}
		}
		if launchMode == "" {
			launchMode = "java-jar"
		}
	}

	switch launchMode {
	case "java-jar":
		if serverJar == "" {
			serverJar, err = selectServerJar01910(root, detection.Platform)
			if err != nil {
				return err
			}
		}
		serverJar, err = hostResolveInsideRoot01910(root, serverJar, true)
		if err != nil {
			return fmt.Errorf("сервер JAR: %w", err)
		}
	case "java-args-file":
		if javaArgsFile == "" {
			javaArgsFile = detectModernForgeArgsFile01910(root, detection.Platform)
		}
		if javaArgsFile == "" {
			return errors.New("Java-args-файл режим требует --Java-args-файл или обнаруживать Forge/NeoForge unix_args/win_args файл")
		}
		javaArgsFile, err = hostResolveInsideRoot01910(root, javaArgsFile, true)
		if err != nil {
			return fmt.Errorf("Java args файл: %w", err)
		}
	default:
		return fmt.Errorf("неподдерживаемый хост запускать режим %q (поддерживаемый: Java-JAR, Java-args-файл)", launchMode)
	}

	jvmArgs := multiFlagValues01910(args, "--jvm-arg")
	serverArgs := multiFlagValues01910(args, "--server-arg")
	if len(serverArgs) == 0 && detection.Family != "proxy" {
		serverArgs = []string{"nogui"}
	}
	restartPolicy := strings.ToLower(strings.TrimSpace(flagValue(args, "--restart-policy", "on-failure")))
	if restartPolicy != "never" && restartPolicy != "on-failure" && restartPolicy != "always" {
		return errors.New("--перезапуск-политика должен быть никогда, на-ошибка, или всегда")
	}
	maxRestarts, err := positiveOrZeroIntFlag01910(args, "--max-restarts", 3)
	if err != nil {
		return err
	}
	backoff, err := positiveOrZeroIntFlag01910(args, "--restart-backoff-ms", 2000)
	if err != nil {
		return err
	}
	stopTimeout, err := positiveIntFlag01910(args, "--stop-timeout-seconds", 30)
	if err != nil {
		return err
	}

	paths := hostPaths01910(root)
	if lock, readErr := readServerBridgeHostLock01910(paths["lock"]); readErr == nil && lock.PID > 0 && updaterProcessAlive0156(lock.PID) {
		return fmt.Errorf("не может reconfigure пока ServerBridge Хост супервизор PID=%d является работающий", lock.PID)
	}
	if runtimeState, readErr := readServerBridgeHostRuntime01910(paths["runtime"]); readErr == nil && runtimeState.ProcessPID > 0 && updaterProcessAlive0156(runtimeState.ProcessPID) {
		return fmt.Errorf("не может reconfigure пока Minecraft процесс PID=%d является работающий", runtimeState.ProcessPID)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	createdAt := now
	if existing, readErr := readServerBridgeHostConfig01910(paths["config"]); readErr == nil && existing.CreatedAt != "" {
		createdAt = existing.CreatedAt
	}
	config := serverBridgeHostConfig01910{
		SchemaVersion: "1.0", ProductVersion: version, ServerRoot: root, Platform: detection.Platform,
		LaunchMode: launchMode, JavaPath: javaPath, JavaMajor: javaMajor, ServerJar: serverJar, JavaArgsFile: javaArgsFile,
		JVMArgs: jvmArgs, ServerArgs: serverArgs, RestartPolicy: restartPolicy, MaxRestarts: maxRestarts,
		RestartBackoffMillis: backoff, StopTimeoutSeconds: stopTimeout, CreatedAt: createdAt, UpdatedAt: now,
	}
	if err := validateServerBridgeHostConfig01910(config); err != nil {
		return err
	}
	if flagBool(args, "--dry-run", false) {
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "dryRun": true, "config": config})
	}
	if err := os.MkdirAll(paths["dir"], 0o700); err != nil {
		return err
	}
	if err := atomicWriteJSON01910(paths["config"], config, 0o600); err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), config)
}

func resolveServerBridgeHostJava01910(explicit string) (string, int, error) {
	candidates := []string{}
	if strings.TrimSpace(explicit) != "" {
		candidates = append(candidates, strings.TrimSpace(explicit))
	} else {
		if value := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_JAVA")); value != "" {
			candidates = append(candidates, value)
		}
		if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
			name := "java"
			if runtime.GOOS == "windows" {
				name = "java.exe"
			}
			candidates = append(candidates, filepath.Join(home, "bin", name))
		}
		candidates = append(candidates, "java")
	}
	var failures []string
	for _, candidate := range candidates {
		resolved := candidate
		if !filepath.IsAbs(resolved) && !strings.ContainsAny(resolved, `/\\`) {
			if found, err := exec.LookPath(resolved); err == nil {
				resolved = found
			} else {
				failures = append(failures, candidate+": "+err.Error())
				continue
			}
		}
		abs, err := filepath.Abs(resolved)
		if err == nil {
			resolved = abs
		}
		info, err := os.Stat(resolved)
		if err != nil || info.IsDir() {
			failures = append(failures, candidate+": executable not found")
			continue
		}
		major, err := javaMajorVersion(resolved)
		if err != nil {
			failures = append(failures, candidate+": "+err.Error())
			continue
		}
		return filepath.Clean(resolved), major, nil
	}
	return "", 0, fmt.Errorf("нет usable Java/JRE found: %s", strings.Join(failures, "; "))
}

func selectServerJar01910(root, platform string) (string, error) {
	candidates := collectServerJarCandidates0199(root)
	filtered := make([]string, 0, len(candidates))
	markers := map[string][]string{
		"velocity": {"velocity"}, "bungeecord": {"bungeecord", "bungee"}, "waterfall": {"waterfall"},
		"bukkit": {"bukkit", "craftbukkit"}, "spigot": {"spigot"}, "paper": {"paper"}, "purpur": {"purpur"}, "folia": {"folia"},
		"fabric": {"fabric"}, "quilt": {"quilt"}, "forge": {"forge"}, "neoforge": {"neoforge"}, "sponge": {"sponge"},
	}
	for _, candidate := range candidates {
		base := strings.ToLower(filepath.Base(candidate))
		if strings.HasPrefix(base, "neverlauncher-") && strings.Contains(base, "-bridge-") {
			continue
		}
		for _, marker := range markers[platform] {
			if strings.Contains(base, marker) {
				filtered = append(filtered, candidate)
				break
			}
		}
	}
	if len(filtered) == 1 {
		return filtered[0], nil
	}
	if len(filtered) > 1 {
		sort.Slice(filtered, func(i, j int) bool { return filepath.Base(filtered[i]) < filepath.Base(filtered[j]) })
		return "", fmt.Errorf("несколько %s сервер JARs обнаруживать (%s); specify --сервер-JAR явно", platform, strings.Join(relativePaths01910(root, filtered), ", "))
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if platform == "vanilla" {
		for _, candidate := range candidates {
			base := strings.ToLower(filepath.Base(candidate))
			if base == "server.jar" || strings.HasPrefix(base, "minecraft_server") {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("не может select %s запускать JAR безопасно; specify --сервер-JAR", platform)
}

func relativePaths01910(root string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, filepath.ToSlash(relativeOrBase0199(root, path)))
	}
	return out
}

func detectModernForgeArgsFile01910(root, platform string) string {
	var pattern string
	switch platform {
	case "neoforge":
		pattern = filepath.Join(root, "libraries", "net", "neoforged", "neoforge", "*", "*")
	case "forge":
		pattern = filepath.Join(root, "libraries", "net", "minecraftforge", "forge", "*", "*")
	default:
		return ""
	}
	matches, _ := filepath.Glob(pattern)
	want := "unix_args.txt"
	if runtime.GOOS == "windows" {
		want = "win_args.txt"
	}
	for _, match := range matches {
		if strings.EqualFold(filepath.Base(match), want) {
			return match
		}
	}
	return ""
}

func hostResolveInsideRoot01910(root, raw string, mustExist bool) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("путь является пустой")
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("путь escapes сервер корень")
	}
	if mustExist {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return "", errors.New("путь является не regular файл")
		}
		realRoot, rootErr := filepath.EvalSymlinks(root)
		realPath, pathErr := filepath.EvalSymlinks(path)
		if rootErr != nil || pathErr != nil {
			return "", errors.New("не может разрешать сервер-корень путь безопасно")
		}
		realRel, relErr := filepath.Rel(realRoot, realPath)
		if relErr != nil || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) {
			return "", errors.New("разрешённый путь escapes сервер корень через символическая ссылка")
		}
		if resolvedInfo, statErr := os.Stat(realPath); statErr != nil || !resolvedInfo.Mode().IsRegular() {
			return "", errors.New("разрешённый путь является не regular файл")
		}
	}
	return path, nil
}

func startServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	paths := hostPaths01910(root)
	config, err := readServerBridgeHostConfig01910(paths["config"])
	if err != nil {
		return fmt.Errorf("хост является не настраивать: %w; запуск `nl server-bridge host configure`", err)
	}
	if err := validateServerBridgeHostConfig01910(config); err != nil {
		return err
	}
	if state, readErr := readServerBridgeHostRuntime01910(paths["runtime"]); readErr == nil && state.ProcessPID > 0 && updaterProcessAlive0156(state.ProcessPID) {
		return fmt.Errorf("Minecraft процесс PID=%d является по-прежнему alive; refusing к запуск второй супервизор", state.ProcessPID)
	}
	if lock, readErr := readServerBridgeHostLock01910(paths["lock"]); readErr == nil && lock.PID > 0 && updaterProcessAlive0156(lock.PID) {
		return fmt.Errorf("ServerBridge Хост блокировка является принадлежащий через актуальный PID=%d", lock.PID)
	}
	if flagBool(args, "--dry-run", false) {
		command, buildErr := serverBridgeHostCommand01910(config)
		if buildErr != nil {
			return buildErr
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "dryRun": true, "action": "start", "command": command, "config": config})
	}
	if err := os.MkdirAll(paths["dir"], 0o700); err != nil {
		return err
	}
	_ = os.Remove(paths["stop"])
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(executable, "server-bridge", "host", "run", "--server-root", root)
	if err := hostPrepareDetachedProcess01910(cmd); err != nil {
		return err
	}
	logFile, err := os.OpenFile(paths["supervisor"], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск ServerBridge Хост супервизор: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		state, readErr := readServerBridgeHostRuntime01910(paths["runtime"])
		if readErr == nil && state.SupervisorPID == pid && (state.Status == "running" || state.Status == "starting" || state.Status == "restarting") {
			return writeOrPrintJSON(flagValue(args, "--output", ""), state)
		}
		if !updaterProcessAlive0156(pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !updaterProcessAlive0156(pid) {
		return fmt.Errorf("ServerBridge Хост супервизор PID=%d выход во время запуск; inspect %s", pid, paths["supervisor"])
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "status": "starting", "supervisorPid": pid, "runtime": paths["runtime"]})
}

func runServerBridgeHostCommand01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	return runServerBridgeHost01910(root, flagBool(args, "--console", false))
}

func runServerBridgeHost01910(root string, console bool) error {
	paths := hostPaths01910(root)
	config, err := readServerBridgeHostConfig01910(paths["config"])
	if err != nil {
		return err
	}
	if err := validateServerBridgeHostConfig01910(config); err != nil {
		return err
	}
	sessionID, err := randomHostSessionID01910()
	if err != nil {
		return err
	}
	if err := acquireServerBridgeHostLock01910(paths["lock"], sessionID); err != nil {
		return err
	}
	defer func() { _ = releaseServerBridgeHostLock01910(paths["lock"], sessionID) }()
	_ = os.Remove(paths["stop"])

	command, err := serverBridgeHostCommand01910(config)
	if err != nil {
		return err
	}
	state := serverBridgeHostRuntime01910{
		SchemaVersion: "1.0", SessionID: sessionID, Status: "starting", Platform: config.Platform,
		SupervisorPID: os.Getpid(), JavaPath: config.JavaPath, JavaMajor: config.JavaMajor,
		Command: command, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := atomicWriteJSON01910(paths["runtime"], state, 0o600); err != nil {
		return err
	}

	for {
		cmd := exec.Command(command[0], command[1:]...)
		cmd.Dir = root
		if err := hostPrepareChildProcess01910(cmd); err != nil {
			state.Status = "failed"
			state.LastError = err.Error()
			_ = atomicWriteJSON01910(paths["runtime"], state, 0o600)
			return err
		}
		stdoutFile, err := os.OpenFile(paths["stdout"], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		stderrFile, err := os.OpenFile(paths["stderr"], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			stdoutFile.Close()
			return err
		}
		combinedFile, err := os.OpenFile(paths["combined"], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			stdoutFile.Close()
			stderrFile.Close()
			return err
		}
		combined := &hostCombinedWriter01910{w: combinedFile}
		cmd.Stdout = &hostStreamWriter01910{raw: stdoutFile, combined: combined, label: "STDOUT", console: console, consoleWriter: os.Stdout}
		cmd.Stderr = &hostStreamWriter01910{raw: stderrFile, combined: combined, label: "STDERR", console: console, consoleWriter: os.Stderr}
		if err := cmd.Start(); err != nil {
			stdoutFile.Close()
			stderrFile.Close()
			combinedFile.Close()
			state.Status = "failed"
			state.LastError = err.Error()
			_ = atomicWriteJSON01910(paths["runtime"], state, 0o600)
			return fmt.Errorf("запуск Minecraft процесс: %w", err)
		}
		state.Status = "running"
		state.ProcessPID = cmd.Process.Pid
		state.ProcessAt = time.Now().UTC().Format(time.RFC3339Nano)
		state.ExitCode = nil
		state.Crashed = false
		state.LastError = ""
		if err := atomicWriteJSON01910(paths["runtime"], state, 0o600); err != nil {
			_ = hostKillProcess01910(cmd.Process.Pid)
			stdoutFile.Close()
			stderrFile.Close()
			combinedFile.Close()
			return err
		}

		waitErr := cmd.Wait()
		stdoutFile.Close()
		stderrFile.Close()
		combinedFile.Close()

		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		} else if waitErr != nil {
			exitCode = -1
		}
		state.ProcessPID = 0
		state.LastExitAt = time.Now().UTC().Format(time.RFC3339Nano)
		state.ExitCode = &exitCode
		state.Crashed = exitCode != 0
		if state.Crashed {
			state.CrashCount++
			state.LastCrashAt = state.LastExitAt
		}
		if waitErr != nil && exitCode == -1 {
			state.LastError = waitErr.Error()
		}
		stopRequested := consumeHostRequest01910(paths["stop"])
		if stopRequested {
			state.Status = "stopped"
			state.Crashed = false
			if err := atomicWriteJSON01910(paths["runtime"], state, 0o600); err != nil {
				return err
			}
			return nil
		}
		shouldRestart := config.RestartPolicy == "always" || (config.RestartPolicy == "on-failure" && exitCode != 0)
		if shouldRestart && state.RestartCount < config.MaxRestarts {
			state.RestartCount++
			state.Status = "restarting"
			if err := atomicWriteJSON01910(paths["runtime"], state, 0o600); err != nil {
				return err
			}
			if config.RestartBackoffMillis > 0 {
				time.Sleep(time.Duration(config.RestartBackoffMillis) * time.Millisecond)
			}
			continue
		}
		if exitCode == 0 {
			state.Status = "exited"
		} else {
			state.Status = "crashed"
		}
		if shouldRestart && state.RestartCount >= config.MaxRestarts {
			state.LastError = fmt.Sprintf("restart limit reached (%d)", config.MaxRestarts)
		}
		if err := atomicWriteJSON01910(paths["runtime"], state, 0o600); err != nil {
			return err
		}
		if waitErr != nil && exitCode != 0 {
			return fmt.Errorf("Minecraft процесс выход с код %d", exitCode)
		}
		return nil
	}
}

func serverBridgeHostCommand01910(config serverBridgeHostConfig01910) ([]string, error) {
	if err := validateServerBridgeHostConfig01910(config); err != nil {
		return nil, err
	}
	args := append([]string{}, config.JVMArgs...)
	switch config.LaunchMode {
	case "java-jar":
		args = append(args, "-jar", config.ServerJar)
	case "java-args-file":
		userJVM := filepath.Join(config.ServerRoot, "user_jvm_args.txt")
		if info, err := os.Stat(userJVM); err == nil && info.Mode().IsRegular() {
			args = append(args, "@"+userJVM)
		}
		args = append(args, "@"+config.JavaArgsFile)
	default:
		return nil, fmt.Errorf("неподдерживаемый хост запускать режим %q", config.LaunchMode)
	}
	args = append(args, config.ServerArgs...)
	return append([]string{config.JavaPath}, args...), nil
}

func validateServerBridgeHostConfig01910(config serverBridgeHostConfig01910) error {
	if config.SchemaVersion != "1.0" || strings.TrimSpace(config.ServerRoot) == "" || !bridgeSupportedPlatform0199(config.Platform) {
		return errors.New("недопустимый ServerBridge Хост конфигурация")
	}
	root, err := canonicalServerRoot0199(config.ServerRoot)
	if err != nil {
		return err
	}
	if filepath.Clean(root) != filepath.Clean(config.ServerRoot) {
		return errors.New("хост конфигурация serverRoot является не канонический")
	}
	if config.JavaPath == "" {
		return errors.New("хост конфигурация JavaPath является пустой")
	}
	major, err := javaMajorVersion(config.JavaPath)
	if err != nil {
		return err
	}
	if config.JavaMajor > 0 && major != config.JavaMajor {
		return fmt.Errorf("настраивать Java изменён крупный версия: ожидаемый %d, получил %d", config.JavaMajor, major)
	}
	if config.LaunchMode == "java-jar" {
		resolved, err := hostResolveInsideRoot01910(root, config.ServerJar, true)
		if err != nil || filepath.Clean(resolved) != filepath.Clean(config.ServerJar) {
			return errors.New("настраивать сервер JAR является недоступный или вне сервер корень")
		}
	} else if config.LaunchMode == "java-args-file" {
		resolved, err := hostResolveInsideRoot01910(root, config.JavaArgsFile, true)
		if err != nil || filepath.Clean(resolved) != filepath.Clean(config.JavaArgsFile) {
			return errors.New("настраивать Java args файл является недоступный или вне сервер корень")
		}
	} else {
		return fmt.Errorf("неподдерживаемый запускать режим %q", config.LaunchMode)
	}
	if config.RestartPolicy != "never" && config.RestartPolicy != "on-failure" && config.RestartPolicy != "always" {
		return errors.New("недопустимый перезапуск политика")
	}
	if config.MaxRestarts < 0 || config.RestartBackoffMillis < 0 || config.StopTimeoutSeconds <= 0 {
		return errors.New("недопустимый хост supervision ограничения")
	}
	return nil
}

func stopServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		return fmt.Errorf("хост среда выполнения недоступный: %w", err)
	}
	if state.ProcessPID <= 0 || !updaterProcessAlive0156(state.ProcessPID) {
		if state.SupervisorPID > 0 && updaterProcessAlive0156(state.SupervisorPID) {
			return fmt.Errorf("супервизор PID=%d является alive но нет Minecraft процесс является регистрировать", state.SupervisorPID)
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "status": "already-stopped", "runtime": state})
	}
	config, err := readServerBridgeHostConfig01910(paths["config"])
	if err != nil {
		return err
	}
	if flagBool(args, "--dry-run", false) {
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "dryRun": true, "action": "stop", "pid": state.ProcessPID})
	}
	if err := atomicWrite0199(paths["stop"], []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
		return err
	}
	if err := hostTerminateProcess01910(state.ProcessPID); err != nil && updaterProcessAlive0156(state.ProcessPID) {
		return err
	}
	timeout := time.Duration(config.StopTimeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !updaterProcessAlive0156(state.ProcessPID) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if updaterProcessAlive0156(state.ProcessPID) {
		if err := hostKillProcess01910(state.ProcessPID); err != nil {
			return fmt.Errorf("graceful остановка timed из и kill ошибка: %w", err)
		}
	}
	for i := 0; i < 50; i++ {
		current, readErr := readServerBridgeHostRuntime01910(paths["runtime"])
		if readErr == nil && current.ProcessPID == 0 && current.Status == "stopped" {
			return writeOrPrintJSON(flagValue(args, "--output", ""), current)
		}
		time.Sleep(40 * time.Millisecond)
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "status": "stopping", "previousPid": state.ProcessPID})
}

func restartServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	paths := hostPaths01910(root)
	oldSupervisor := 0
	if state, readErr := readServerBridgeHostRuntime01910(paths["runtime"]); readErr == nil {
		oldSupervisor = state.SupervisorPID
		if state.ProcessPID > 0 && updaterProcessAlive0156(state.ProcessPID) {
			stopArgs := []string{"--server-root", root}
			if err := stopServerBridgeHost01910(stopArgs); err != nil {
				return err
			}
		}
	}
	if oldSupervisor > 0 && oldSupervisor != os.Getpid() {
		deadline := time.Now().Add(5 * time.Second)
		for updaterProcessAlive0156(oldSupervisor) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if updaterProcessAlive0156(oldSupervisor) {
			return fmt.Errorf("предыдущий ServerBridge Хост супервизор PID=%d сделал не выход после остановка", oldSupervisor)
		}
	}
	return startServerBridgeHost01910(append([]string{"--server-root", root}, passThroughFlag01910(args, "--output")...))
}

func statusServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	paths := hostPaths01910(root)
	config, configErr := readServerBridgeHostConfig01910(paths["config"])
	state, stateErr := readServerBridgeHostRuntime01910(paths["runtime"])
	result := map[string]any{"schemaVersion": "1.0", "productVersion": version, "serverRoot": root, "configured": configErr == nil}
	if configErr == nil {
		result["config"] = config
	} else {
		result["configError"] = configErr.Error()
	}
	if stateErr == nil {
		result["runtime"] = state
		result["supervisorAlive"] = state.SupervisorPID > 0 && updaterProcessAlive0156(state.SupervisorPID)
		result["processAlive"] = state.ProcessPID > 0 && updaterProcessAlive0156(state.ProcessPID)
	} else {
		result["status"] = "not-started"
	}
	result["logs"] = map[string]string{"stdout": paths["stdout"], "stderr": paths["stderr"], "combined": paths["combined"], "supervisor": paths["supervisor"]}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

func logsServerBridgeHost01910(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	paths := hostPaths01910(root)
	stream := strings.ToLower(strings.TrimSpace(flagValue(args, "--stream", "all")))
	path := paths["combined"]
	switch stream {
	case "all", "combined":
	case "stdout":
		path = paths["stdout"]
	case "stderr":
		path = paths["stderr"]
	case "supervisor":
		path = paths["supervisor"]
	default:
		return errors.New("--поток должен быть все, стандартный вывод, стандартный поток ошибок, или супервизор")
	}
	lines, err := positiveIntFlag01910(args, "--lines", 100)
	if err != nil {
		return err
	}
	if err := printTail01910(path, lines); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("журнал поток делает не exist yet: %s", path)
		}
		return err
	}
	if !flagBool(args, "--follow", false) {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	buf := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				return err
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		state, stateErr := readServerBridgeHostRuntime01910(paths["runtime"])
		if stateErr == nil && state.ProcessPID == 0 && !updaterProcessAlive0156(state.SupervisorPID) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func printTail01910(path string, maxLines int) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	lines := make([]string, 0, maxLines)
	for scanner.Scan() {
		if len(lines) == maxLines {
			copy(lines, lines[1:])
			lines[len(lines)-1] = scanner.Text()
		} else {
			lines = append(lines, scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}

func acquireServerBridgeHostLock01910(path, sessionID string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		lock := serverBridgeHostLock01910{SchemaVersion: "1.0", PID: os.Getpid(), SessionID: sessionID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		data, _ := json.Marshal(lock)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if _, writeErr := file.Write(append(data, '\n')); writeErr != nil {
				file.Close()
				_ = os.Remove(path)
				return writeErr
			}
			return file.Close()
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := readServerBridgeHostLock01910(path)
		if readErr == nil && existing.PID > 0 && updaterProcessAlive0156(existing.PID) {
			return fmt.Errorf("ServerBridge Хост является уже контролируемый через PID=%d", existing.PID)
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	return errors.New("может не acquire ServerBridge Хост блокировка")
}

func releaseServerBridgeHostLock01910(path, sessionID string) error {
	lock, err := readServerBridgeHostLock01910(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if lock.SessionID != sessionID || lock.PID != os.Getpid() {
		return errors.New("refusing к удалять ServerBridge Хост блокировка принадлежащий через другой сессия")
	}
	return os.Remove(path)
}

func readServerBridgeHostConfig01910(path string) (serverBridgeHostConfig01910, error) {
	var value serverBridgeHostConfig01910
	err := readJSONFile01910(path, &value)
	return value, err
}

func readServerBridgeHostRuntime01910(path string) (serverBridgeHostRuntime01910, error) {
	var value serverBridgeHostRuntime01910
	err := readJSONFile01910(path, &value)
	return value, err
}

func readServerBridgeHostLock01910(path string) (serverBridgeHostLock01910, error) {
	var value serverBridgeHostLock01910
	err := readJSONFile01910(path, &value)
	return value, err
}

func readJSONFile01910(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing non-regular состояние файл: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func atomicWriteJSON01910(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite0199(path, append(data, '\n'), mode)
}

func randomHostSessionID01910() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func consumeHostRequest01910(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	_ = os.Remove(path)
	return true
}

func multiFlagValues01910(args []string, name string) []string {
	values := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			values = append(values, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(args[i], name+"=") {
			values = append(values, strings.TrimPrefix(args[i], name+"="))
		}
	}
	return values
}

func positiveIntFlag01910(args []string, name string, fallback int) (int, error) {
	value := strings.TrimSpace(flagValue(args, name, ""))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s должен быть positive integer", name)
	}
	return parsed, nil
}

func positiveOrZeroIntFlag01910(args []string, name string, fallback int) (int, error) {
	value := strings.TrimSpace(flagValue(args, name, ""))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s должен быть non-negative integer", name)
	}
	return parsed, nil
}

func passThroughFlag01910(args []string, name string) []string {
	if value := flagValue(args, name, ""); value != "" {
		return []string{name, value}
	}
	return nil
}
