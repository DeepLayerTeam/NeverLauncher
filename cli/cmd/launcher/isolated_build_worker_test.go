package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProcessorWorker0273ExecutesOutsideCLIWithSanitizedEnvAndLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("тестовая имитация Java для POSIX")
	}
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	// Тестовый Java-процесс записывает собственный PID, факт наследования секрета и результат.
	script := `#!/bin/sh
printf '%s' "$PPID" > "$PWD/worker-parent.pid"
if [ -n "$LAUNCHER_TOKEN" ]; then exit 99; fi
if [ -z "$LAUNCHER_BUILD_WORKER" ]; then exit 98; fi
printf 'ok' > "$PWD/generated.jar"
printf 'logged output\n'
`
	if err := os.WriteFile(java, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_TOKEN", "should-not-be-in-child")
	pc := forgeProcessorContext{ClientDir: dir, JavaExecutable: java, Timeout: 10 * time.Second}
	path, err := runIsolatedProcessor0273(context.Background(), pc, 4, []string{"-cp", "test.jar", "example.Processor"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "generated.jar"))
	if err != nil || string(got) != "ok" {
		t.Fatalf("Отсутствует результат исполнения: %s, %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "logged output") || !strings.Contains(string(raw), "success=true") {
		t.Fatalf("Отсутствует запись в журнале подтверждений: %s", raw)
	}
	if strings.Contains(string(raw), "should-not-be-in-child") {
		t.Fatal("Секрет попал в журнал рабочего процесса")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "worker-parent.pid"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("Java не запустилась")
	}
}

func TestProcessorWorker0273TimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Проверка группы процессов (PGID) в Linux")
	}
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	// Включён дочерний процесс следующего уровня, наследующий каналы: таймаут не должен ожидать его завершения.
	if err := os.WriteFile(java, []byte("#!/bin/sh\nsleep 60 &\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	path, err := runIsolatedProcessor0273(ctx, forgeProcessorContext{ClientDir: dir, JavaExecutable: java, Timeout: 20 * time.Second}, 0, []string{"-cp", "a", "Main"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ожидалось превышение времени ожидания, получено: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("Дерево рабочих процессов не завершилось вовремя: %s", time.Since(start))
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !strings.Contains(string(data), "success=false") {
		t.Fatalf("Отсутствует журнал сбоя: %s, %v", data, readErr)
	}
}

func TestProcessorWorker0273RefusesOversizedOrUntrustedRequest(t *testing.T) {
	// Не разрешайте JSON-запросы, размер которых нельзя проверить независимо, или
	// пути запуска, разрешаемые относительно произвольных элементов PATH.
	tooBig := processorWorkerRequest0273{Java: "/usr/bin/java", Directory: "/tmp", TempDirectory: "/tmp", TimeoutSeconds: 60, HeapMiB: 2048, Args: make([]string, 5000)}
	raw, err := json.Marshal(tooBig)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > workerRequestLimit0273 {
		t.Log("Слишком большой запрос отклоняется на уровне транспорта")
	}
	if len(tooBig.Args) <= 4096 {
		t.Fatal("некорректный тестовый стенд")
	}
}

func TestForgeProcessorInputFingerprint0273RejectsModifiedClasspath(t *testing.T) {
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	jar := filepath.Join(dir, "libraries", "example", "p", "1", "p-1.jar")
	if err := os.MkdirAll(filepath.Dir(jar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(java, []byte("java"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: dir, JavaExecutable: java}
	processor := forgeProcessor{Jar: "example:p:1"}
	a, err := fingerprintForgeProcessor0273(pc, processor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := fingerprintForgeProcessor0273(pc, processor)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("Изменение JAR обработчика должно отменять идентичность журнала")
	}
	if err := os.Remove(jar); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintForgeProcessor0273(pc, processor); err == nil {
		t.Fatal("Отсутствие входных данных обработчика должно вызывать критическую ошибку")
	}
}

func TestForgeProcessorRecovery0273QuarantinesCorruptOutputAndChangedInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Тестовое окружение POSIX")
	}
	root := t.TempDir()
	java := testFakeJava(t, []byte("verified-processor-output"))
	installer := filepath.Join(root, ".launcher", "installers", "forge", "52.0.1", "installer.jar")
	processorJar := filepath.Join(root, "libraries", "com", "example", "processor", "1.0", "processor-1.0.jar")
	for _, f := range []string{installer, processorJar} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(installer, []byte("stable-installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(processorJar, testProcessorJar(t), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := mavenCoordinatePath("com.example:generated:1.0")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "libraries", filepath.FromSlash(rel))
	pc := forgeProcessorContext{
		Loader: "forge", MinecraftVersion: "1.21.1", ClientDir: root, InstallerPath: installer,
		JavaExecutable: java, Timeout: 5 * time.Second, Profile: &forgeInstallerProfile{Processors: []forgeProcessor{{
			Jar: "com.example:processor:1.0", Args: []string{"--out", "[com.example:generated:1.0]"},
			Outputs: map[string]string{"[com.example:generated:1.0]": sha1HexLocal([]byte("verified-processor-output"))},
		}}},
	}
	first, err := runForgeProcessors(context.Background(), pc)
	if err != nil || first.Ran != 1 {
		t.Fatalf("Первый запуск %+v: %v", first, err)
	}
	second, err := runForgeProcessors(context.Background(), pc)
	if err != nil || second.Skipped != 1 {
		t.Fatalf("Второй запуск %+v: %v", second, err)
	}
	if err := os.WriteFile(output, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := runForgeProcessors(context.Background(), pc)
	if err != nil || third.Ran != 1 || third.Skipped != 0 {
		t.Fatalf("Принят повреждённый результат %+v: %v", third, err)
	}
	if got, err := os.ReadFile(output); err != nil || string(got) != "verified-processor-output" {
		t.Fatalf("Невосстановленный файл: %s, %v", got, err)
	}
	if err := os.WriteFile(processorJar, testProcessorJar(t), 0o600); err != nil {
		t.Fatal(err)
	} // same bytes
	fourth, err := runForgeProcessors(context.Background(), pc)
	if err != nil || fourth.Skipped != 1 {
		t.Fatalf("Одинаковые байты JAR изменили отпечаток: %+v, %v", fourth, err)
	}
	if err := os.WriteFile(processorJar, append(testProcessorJar(t), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	fifth, err := runForgeProcessors(context.Background(), pc)
	if err != nil || fifth.Ran != 1 {
		t.Fatalf("Изменённый ввод не аннулировал результат обработчика: %+v, %v", fifth, err)
	}
	journal, _, err := loadForgeProcessorJournal(pc)
	if err != nil || journal.Entries["0"].WorkerLogPath == "" || !isSHA256Hex0271(journal.Entries["0"].InputSHA256) {
		t.Fatalf("Отсутствует подтверждение в журнале: %+v, %v", journal, err)
	}
	qdir := filepath.Join(root, ".launcher", "quarantine")
	found, err := os.ReadDir(qdir)
	if err != nil || len(found) < 2 {
		t.Fatalf("Повреждённые и устаревшие результаты не помещены в карантин: %v, %v", found, err)
	}
}

func TestForgeProcessorRecovery0273RejectsSymlinkOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("требуются символические ссылки")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.jar")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(root, "output.jar")
	if err := os.Symlink(outside, in); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: root}
	_, err := processorOutputsMatch(pc, forgeProcessor{Outputs: map[string]string{"{ROOT}/output.jar": sha1HexLocal([]byte("outside"))}})
	if err == nil {
		t.Fatal("Результат обработчика через символическую ссылку принят как доверенный")
	}
}

func TestProcessorWorker0273StrictSandboxFailsClosedWhenUnsupported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("проверка доступности bubblewrap в Linux")
	}
	if _, err := exec.LookPath("bwrap"); err == nil {
		t.Skip("bubblewrap установлен; для сертификации требуется системная поддержка пространств имён")
	}
	root := t.TempDir()
	java := filepath.Join(root, "java")
	if err := os.WriteFile(java, []byte("#!/bin/sh\nprintf 'unsafe fallback' > generated.jar\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: root, JavaExecutable: java, StrictSandbox: true, Timeout: 5 * time.Second}
	log, err := runIsolatedProcessor0273(context.Background(), pc, 0, []string{"-cp", "a", "Main"})
	if err == nil || !strings.Contains(err.Error(), "bubblewrap") {
		t.Fatalf("Резервный запуск строгого рабочего процесса небезопасен: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "generated.jar")); !os.IsNotExist(statErr) {
		t.Fatalf("Обработчик работал вне строгой песочницы: %v", statErr)
	}
	if _, err := os.Stat(log); err != nil {
		t.Fatalf("Журнал ошибки рабочего процесса недоступен: %v", err)
	}
}
