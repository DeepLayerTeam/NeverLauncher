//go:build linux && arm64

package linuxsandbox

// Linux AArch64 использует универсальный ABI системных вызовов, а не ABI
// x86_64. Архитектура аудита — AUDIT_ARCH_AARCH64, 64 бита, little-endian. Эти
// номера запретов относятся к Linux/arm64; их соответствие политике x86_64
// необходимо пересматривать при изменении любой политики.
const (
	sandboxAuditArch     uint32 = 0xc00000b7
	sandboxClone3Syscall uint32 = 435
	sandboxRejectX32            = false
)

// Запрещённые операции: ptrace, pivot_root, chroot, mount/umount, операции с
// модулями, kexec, управление ключами, unshare, perf/fanotify, открытие через
// дескрипторы, setns, process_vm_*, finit_module, seccomp, BPF, userfaultfd,
// io_uring, новый API монтирования, clone3 и mount_setattr. Clone(2) отдельно
// фильтруется по флагам пространств имён общей реализацией блокировки. Для clone3
// возвращается ENOSYS, чтобы libc/Go безопасно переходили на clone(2).
var sandboxDeniedSyscalls = []uint32{
	117, 41, 51, 40, 39, 105, 106, 104, 217, 218, 219,
	97, 241, 262, 265, 268, 270, 271, 273, 277, 280, 282,
	425, 426, 427, 428, 429, 430, 431, 432, 433, 435, 442,
	// Изменения глобальных привилегий хоста недопустимы для недоверенного
	// воркера.
	92, 142, 224, 225, 294,
}
