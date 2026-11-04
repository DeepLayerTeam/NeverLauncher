//go:build linux && arm64

package linuxsandbox

// Универсальный ABI системных вызовов Linux AArch64 (SYS_memfd_create).
const sandboxMemfdCreateSyscall uintptr = 279
