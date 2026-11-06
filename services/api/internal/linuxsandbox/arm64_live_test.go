//go:build linux && arm64

package linuxsandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Выполняется на настоящем ядре AArch64 с пространствами имён пользователя и
// делегированной cgroup v2. Проверочный объект — настоящий недоверенный ELF, а
// не оценщик политики песочницы. Нельзя сертифицировать возможность по mock или
// одной успешной кросс-компиляции.
func TestARM64NativeKernelBoundary0439(t *testing.T) {
	if os.Getenv("NL_RUN_LIVE_LINUX_SANDBOX") != "1" {
		t.Skip("Требуется реальный узел AArch64 с делегированием cgroup для изоляции")
	}
	if err := Available(); err != nil {
		t.Fatalf("Изоляция AArch64 недоступна: %v", err)
	}
	opt := validOptions0319(t)
	opt.Policy.TimeoutSeconds = 20
	opt.Policy.MaxProcesses = 20
	opt.Policy.MaxCPUPercent = 50
	probe := filepath.Join(opt.PayloadRoot, "arm64-probe")
	src := filepath.Join(t.TempDir(), "probe.go")
	// Вызывайте реальные точки входа системных вызовов Runtime внутри
	// изолированного расширения. Проверяйте фактические ошибки ядра, а не только
	// настройки политики.
	code := `package main
import("fmt"; "os"; "strings"; "syscall")
func main() {
 b,e:=os.ReadFile("/proc/self/status");if e!=nil{panic(e)}
 s:=string(b)
 for _,needle:=range []string{"NoNewPrivs:\t1","Seccomp:\t2","CapEff:\t0000000000000000"}{if !strings.Contains(s,needle){panic("изоляция не активирована: "+needle)}}
 for _,num:=range []uintptr{40,97,268,280,435,442}{
  _,_,errno:=syscall.RawSyscall(num,0,0,0)
  if num==435 {if errno!=syscall.ENOSYS {panic(fmt.Sprintf("clone3: %v",errno))}}
  else if errno!=syscall.EPERM {panic(fmt.Sprintf("системный вызов %d не заблокирован seccomp: %v",num,errno))}
 }
 if _,e:=os.Stat("/etc/passwd");!os.IsNotExist(e){panic("файловая система хоста доступна из изоляции")}
 if _,e:=os.Stat("/package/arm64-probe");e!=nil{panic("пакет только для чтения не найден")}
 fmt.Println("arm64-seccomp-namespaces-ok")
}`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-trimpath", "-o", probe, src)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Компиляция нативной проверки arm64: %v: %s", err, output)
	}
	opt.Entrypoint = probe
	h, err := Prepare(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var stdout, stderr bytes.Buffer
	h.Cmd.Stdout = &stdout
	h.Cmd.Stderr = &stderr
	if err := h.Cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.Started(); err != nil {
		t.Fatalf("Запуск изолированной среды: %v: %s", err, stderr.String())
	}
	result := make(chan error, 1)
	go func() { result <- h.Cmd.Wait() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Сбой изолированного процесса: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(15 * time.Second):
		h.Close()
		t.Fatal("Изолированный процесс превысил лимит времени")
	}
	if !strings.Contains(stdout.String(), "arm64-seccomp-namespaces-ok") {
		t.Fatalf("Изолированный процесс не подтвердил применение политики: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
