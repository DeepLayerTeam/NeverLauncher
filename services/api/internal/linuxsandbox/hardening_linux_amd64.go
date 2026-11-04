//go:build linux && amd64

package linuxsandbox

// Константы из ABI системных вызовов Linux x86_64 и AUDIT_ARCH_X86_64. При
// добавлении arm64 сохраняйте существующую политику amd64.
const (
	sandboxAuditArch     uint32 = 0xc000003e
	sandboxClone3Syscall uint32 = 435
	sandboxRejectX32            = true
)

var sandboxDeniedSyscalls = []uint32{
	101, 155, 161, 165, 166, 175, 176, 246, 248, 249, 250,
	272, 298, 300, 304, 308, 310, 311, 313, 321, 323,
	425, 428, 429, 430, 431, 432, 433, 435, 442,
}
