//go:build linux && arm64

package linuxsandbox

import "testing"

func TestARM64SeccompArchitecture0439(t *testing.T) {
	if sandboxAuditArch != 0xc00000b7 || sandboxMemfdCreateSyscall != 279 || sandboxRejectX32 {
		t.Fatal("unexpected AArch64 Linux kernel ABI")
	}
	// Эти номера должны соответствовать ABI Linux AArch64, а не x86-64.
	for _, num := range []uint32{40, 41, 97, 117, 219, 241, 265, 268, 277, 280, 282, 425, 426, 427, 435, 442} {
		if !containsDeniedSyscall0439(num) {
			t.Fatalf("security-sensitive arm64 syscall %d not blocked", num)
		}
	}
}
