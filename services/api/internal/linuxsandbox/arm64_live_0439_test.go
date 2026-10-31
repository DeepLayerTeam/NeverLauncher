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

// This is executed on a real AArch64 kernel with user namespaces and a
// delegated cgroup v2. Its probe is a genuine untrusted guest ELF, not the
// sandbox's policy evaluator. Do not certify this capability from a mock or
// successful cross compilation alone.
func TestARM64NativeKernelBoundary0439(t *testing.T) {
	if os.Getenv("NL_RUN_LIVE_LINUX_SANDBOX") != "1" {
		t.Skip("native AArch64 cgroup-delegated sandbox host required")
	}
	if err := Available(); err != nil {
		t.Fatalf("AArch64 isolation unavailable: %v", err)
	}
	opt := validOptions0319(t)
	opt.Policy.TimeoutSeconds = 20
	opt.Policy.MaxProcesses = 20
	opt.Policy.MaxCPUPercent = 50
	probe := filepath.Join(opt.PayloadRoot, "arm64-probe")
	src := filepath.Join(t.TempDir(), "probe.go")
	// Use the real runtime's syscall entrypoints from inside the jailed
	// extension. Check actual kernel errors, not merely configured policy.
	code := `package main
import("fmt"; "os"; "strings"; "syscall")
func main() {
 b,e:=os.ReadFile("/proc/self/status");if e!=nil{panic(e)}
 s:=string(b)
 for _,needle:=range []string{"NoNewPrivs:\t1","Seccomp:\t2","CapEff:\t0000000000000000"}{if !strings.Contains(s,needle){panic("isolation not active: "+needle)}}
 for _,num:=range []uintptr{40,97,268,280,435,442}{
  _,_,errno:=syscall.RawSyscall(num,0,0,0)
  if num==435 {if errno!=syscall.ENOSYS {panic(fmt.Sprintf("clone3: %v",errno))}}
  else if errno!=syscall.EPERM {panic(fmt.Sprintf("syscall %d not seccomp-denied: %v",num,errno))}
 }
 if _,e:=os.Stat("/etc/passwd");!os.IsNotExist(e){panic("host filesystem reachable")}
 if _,e:=os.Stat("/package/arm64-probe");e!=nil{panic("readonly package missing")}
 fmt.Println("arm64-seccomp-namespaces-ok")
}`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-trimpath", "-o", probe, src)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile native arm64 probe: %v: %s", err, output)
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
		t.Fatalf("sandbox bootstrap: %v: %s", err, stderr.String())
	}
	result := make(chan error, 1)
	go func() { result <- h.Cmd.Wait() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("isolated guest failed: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(15 * time.Second):
		h.Close()
		t.Fatal("isolated guest exceeded deadline")
	}
	if !strings.Contains(stdout.String(), "arm64-seccomp-namespaces-ok") {
		t.Fatalf("guest did not demonstrate policy: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
