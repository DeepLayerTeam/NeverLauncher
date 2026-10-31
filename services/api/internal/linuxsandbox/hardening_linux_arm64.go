//go:build linux && arm64

package linuxsandbox

// Linux AArch64 uses the generic syscall ABI (not the x86_64 ABI). The
// audit architecture is AUDIT_ARCH_AARCH64 (little-endian, 64-bit).
// These deny numbers are Linux/arm64 syscall numbers; their correspondence
// to the x86_64 policy must be reviewed when either policy changes.
const (
	sandboxAuditArch     uint32 = 0xc00000b7
	sandboxClone3Syscall uint32 = 435
	sandboxRejectX32            = false
)

// Forbidden operations: ptrace, pivot_root, chroot, mount/umount, module
// operations, kexec, key management, unshare, perf/fanotify, handle-based
// opens, setns, process_vm_*, finit_module, seccomp, BPF, userfaultfd,
// io_uring, the new mount API, clone3 and mount_setattr. Clone(2) is filtered
// separately by the namespace flags in the shared lockdown implementation.
// Clone3 is denied with ENOSYS so libc/Go can safely fall back to clone(2).
var sandboxDeniedSyscalls = []uint32{
	117, 41, 51, 40, 39, 105, 106, 104, 217, 218, 219,
	97, 241, 262, 265, 268, 270, 271, 273, 277, 280, 282,
	425, 426, 427, 428, 429, 430, 431, 432, 433, 435, 442,
	// Host-global privilege changes do not belong to an untrusted worker.
	92, 142, 224, 225, 294,
}
