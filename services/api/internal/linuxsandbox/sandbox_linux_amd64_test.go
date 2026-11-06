//go:build linux && amd64

package linuxsandbox

import "testing"

func TestAMD64SeccompArchitecture0439(t *testing.T) {
	if sandboxAuditArch != 0xc000003e || sandboxMemfdCreateSyscall != 319 || !sandboxRejectX32 {
		t.Fatal("Неожиданный ABI ядра Linux для x86-64")
	}
	if !containsDeniedSyscall0439(sandboxClone3Syscall) {
		t.Fatal("Системный вызов clone3 должен быть запрещён")
	}
}
