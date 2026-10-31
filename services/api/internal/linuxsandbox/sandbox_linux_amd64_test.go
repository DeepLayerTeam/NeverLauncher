//go:build linux && amd64

package linuxsandbox

import "testing"

func TestAMD64SeccompArchitecture0439(t *testing.T) {
	if sandboxAuditArch != 0xc000003e || sandboxMemfdCreateSyscall != 319 || !sandboxRejectX32 {
		t.Fatal("unexpected x86-64 Linux kernel ABI")
	}
	if !containsDeniedSyscall0439(sandboxClone3Syscall) {
		t.Fatal("clone3 must be denied")
	}
}
