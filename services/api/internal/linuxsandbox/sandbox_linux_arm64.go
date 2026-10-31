//go:build linux && arm64

package linuxsandbox

// Linux AArch64 generic syscall ABI (SYS_memfd_create).
const sandboxMemfdCreateSyscall uintptr = 279
