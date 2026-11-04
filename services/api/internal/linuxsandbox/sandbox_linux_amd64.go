//go:build linux && amd64

package linuxsandbox

// ABI системных вызовов Linux x86-64 (SYS_memfd_create).
const sandboxMemfdCreateSyscall uintptr = 319
