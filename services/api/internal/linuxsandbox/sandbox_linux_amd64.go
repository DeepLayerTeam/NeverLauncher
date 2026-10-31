//go:build linux && amd64

package linuxsandbox

// Linux x86-64 syscall ABI (SYS_memfd_create).
const sandboxMemfdCreateSyscall uintptr = 319
