//go:build linux && amd64

package linuxsandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const sysMountSetattr = 442
const atRecursive = 0x8000
const mountAttrReadonly = 0x1
const mountAttrNosuid = 0x2
const mountAttrNodev = 0x4

type mountAttr struct {
	Set         uint64
	Clear       uint64
	Propagation uint64
	UsernsFD    uint64
}

func roRecursive(path string, nodev bool) error {
	flags := uint64(mountAttrReadonly | mountAttrNosuid)
	if nodev {
		flags |= mountAttrNodev
	}
	p, e := syscall.BytePtrFromString(path)
	if e != nil {
		return e
	}
	empty := []byte{0}
	attr := mountAttr{Set: flags}
	_, _, errno := syscall.RawSyscall6(sysMountSetattr, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&empty[0])), atRecursive, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("mount_setattr recursive RO %s: %w", path, errno)
	}
	return nil
}
func bindRO(from, to string, nodev bool) error {
	info, e := os.Stat(from)
	if e != nil {
		return e
	}
	if info.IsDir() {
		if e = os.MkdirAll(to, 0o755); e != nil {
			return e
		}
	} else {
		if e = os.MkdirAll(filepath.Dir(to), 0o755); e != nil {
			return e
		}
		f, er := os.OpenFile(to, os.O_CREATE|os.O_EXCL, 0o644)
		if er != nil {
			return er
		}
		_ = f.Close()
	}
	if e = syscall.Mount(from, to, "", syscall.MS_BIND|syscall.MS_REC, ""); e != nil {
		return e
	}
	return roRecursive(to, nodev)
}
func setupMounts(c childConfig) error {
	if c.RootDir == "" || !strings.HasPrefix(c.RootDir, "/tmp/nl-sandbox-0319-") {
		return errors.New("invalid private root")
	}
	if e := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); e != nil {
		return fmt.Errorf("private mount tree: %w", e)
	}
	if e := syscall.Mount("tmpfs", c.RootDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=32m"); e != nil {
		return fmt.Errorf("private root tmpfs: %w", e)
	}
	root := c.RootDir
	for _, d := range []string{"package", "usr", "tmp", "scratch", "proc", "dev", ".oldroot"} {
		if e := os.MkdirAll(filepath.Join(root, d), 0o755); e != nil {
			return e
		}
	}
	if e := bindRO(c.PayloadRoot, filepath.Join(root, "package"), true); e != nil {
		return fmt.Errorf("package readonly mount: %w", e)
	}
	// Only runtime libraries/executables are exposed, never /etc, /home,
	// /var, /run or the backend's private files. Recursive RO applies even
	// if /usr contains additional submounts.
	for _, dir := range []string{"usr", "bin", "lib", "lib64", "sbin"} {
		host := "/" + dir
		info, e := os.Lstat(host)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		dst := filepath.Join(root, dir)
		if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(host)
			if e != nil {
				return e
			}
			if e := os.Symlink(target, dst); e != nil {
				return e
			}
		} else if info.IsDir() {
			if e := bindRO(host, dst, true); e != nil {
				return fmt.Errorf("runtime %s: %w", host, e)
			}
		}
	}
	// Dynamic ELF loaders need their cache, but /etc is intentionally absent.
	if _, e := os.Stat("/etc/ld.so.cache"); e == nil {
		if e := bindRO("/etc/ld.so.cache", filepath.Join(root, "etc/ld.so.cache"), true); e != nil {
			return e
		}
	}
	for _, src := range []string{"/etc/ssl/certs", "/etc/ssl/cert.pem"} {
		if _, e := os.Stat(src); e == nil {
			if e := bindRO(src, filepath.Join(root, src), true); e != nil {
				return e
			}
		}
	}
	if e := syscall.Mount("tmpfs", filepath.Join(root, "tmp"), "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=1777,size=32m"); e != nil {
		return e
	}
	scratchSize := c.Policy.MaxMemoryBytes / 4
	if scratchSize > 64<<20 {
		scratchSize = 64 << 20
	}
	if scratchSize < 1<<20 {
		scratchSize = 1 << 20
	}
	if e := syscall.Mount("tmpfs", filepath.Join(root, "scratch"), "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700,size="+strconv.FormatInt(scratchSize, 10)); e != nil {
		return e
	}
	if e := syscall.Mount("tmpfs", filepath.Join(root, "dev"), "tmpfs", syscall.MS_NOSUID, "mode=0755,size=1m"); e != nil {
		return e
	}
	for _, name := range []string{"null", "zero", "random", "urandom"} {
		dst := filepath.Join(root, "dev", name)
		f, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL, 0o644)
		if e != nil {
			return e
		}
		_ = f.Close()
		if e := syscall.Mount("/dev/"+name, dst, "", syscall.MS_BIND, ""); e != nil {
			return fmt.Errorf("device %s: %w", name, e)
		}
	}
	if e := syscall.Mount("proc", filepath.Join(root, "proc"), "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_RDONLY, ""); e != nil {
		return fmt.Errorf("private procfs: %w", e)
	}
	if e := syscall.PivotRoot(root, filepath.Join(root, ".oldroot")); e != nil {
		return fmt.Errorf("pivot_root: %w", e)
	}
	if e := os.Chdir("/"); e != nil {
		return e
	}
	if e := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); e != nil {
		return fmt.Errorf("old root detach: %w", e)
	}
	return os.Remove("/.oldroot")
}

// Bring up only loopback inside the newly created network namespace.
// Neither veth nor host routing is configured; the only host connection is
// the pre-opened, authenticated HTTP protocol socketpair.
func enableLoopback() error {
	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	type ifreq struct {
		Name    [16]byte
		Flags   uint16
		Padding [22]byte
	}
	var req ifreq
	copy(req.Name[:], "lo")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	req.Flags |= uint16(syscall.IFF_UP | syscall.IFF_RUNNING)
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}
type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

const (
	bpfLDWABS                 = 0x20
	bpfJMPJEQK                = 0x15
	bpfJMPJSETK               = 0x45
	bpfRETK                   = 0x06
	seccompAllow              = 0x7fff0000
	seccompErrno              = 0x00050000
	auditArchAMD64            = 0xc000003e
	prSetNoNewPrivs           = 38
	prSetSeccomp              = 22
	seccompModeFilter         = 2
	prSetSecurebits           = 28
	secureNoRoot              = 1
	secureNoRootLocked        = 2
	secureNoSetuidFixup       = 4
	secureNoSetuidFixupLocked = 8
)

func lockdown() error {
	if _, _, er := syscall.RawSyscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0); er != 0 {
		return er
	} // PR_SET_DUMPABLE=0
	// No root or file capabilities may be regained across execve.
	if _, _, er := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetSecurebits, secureNoRoot|secureNoRootLocked|secureNoSetuidFixup|secureNoSetuidFixupLocked, 0, 0, 0, 0); er != 0 {
		return er
	}
	// Linux V3 capset structure, two 32-bit words for all 64 capabilities.
	type header struct {
		Version uint32
		Pid     int32
	}
	type capData struct {
		Effective   uint32
		Permitted   uint32
		Inheritable uint32
	}
	hdr := header{Version: 0x20080522}
	data := [2]capData{}
	if _, _, er := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); er != 0 {
		return er
	}
	if _, _, er := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); er != 0 {
		return er
	}
	deny := []uint32{101, 155, 161, 165, 166, 175, 176, 246, 248, 249, 250, 272, 298, 300, 304, 308, 310, 311, 313, 321, 323, 425, 428, 429, 430, 431, 432, 433, 435, 442}
	prog := []sockFilter{
		{Code: bpfLDWABS, K: 4},
		{Code: bpfJMPJEQK, Jt: 1, Jf: 0, K: auditArchAMD64},
		{Code: bpfRETK, K: seccompErrno | uint32(syscall.EPERM)},
		{Code: bpfLDWABS, K: 0},
		{Code: bpfJMPJSETK, Jt: 0, Jf: 1, K: 0x40000000},
		{Code: bpfRETK, K: seccompErrno | uint32(syscall.EPERM)},
	}
	for _, num := range deny {
		action := uint32(seccompErrno | uint32(syscall.EPERM))
		if num == 435 {
			action = seccompErrno | uint32(syscall.ENOSYS)
		}
		prog = append(prog, sockFilter{Code: bpfJMPJEQK, Jt: 0, Jf: 1, K: num}, sockFilter{Code: bpfRETK, K: action})
	}
	// clone(2) normal threads/processes remain permitted, but creating a new
	// namespace with CLONE_NEW* flags is prohibited after the boundary exists.
	namespaceMask := uint32(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS)
	prog = append(prog,
		sockFilter{Code: bpfJMPJEQK, Jt: 0, Jf: 3, K: uint32(syscall.SYS_CLONE)},
		sockFilter{Code: bpfLDWABS, K: 16},
		sockFilter{Code: bpfJMPJSETK, Jt: 0, Jf: 1, K: namespaceMask},
		sockFilter{Code: bpfRETK, K: seccompErrno | uint32(syscall.EPERM)},
		sockFilter{Code: bpfRETK, K: seccompAllow},
	)
	filter := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, er := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&filter)), 0, 0, 0); er != 0 {
		return er
	}
	return nil
}
func verifyLocked() error {
	data, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	if !strings.Contains(string(data), "NoNewPrivs:\t1") || !strings.Contains(string(data), "Seccomp:\t2") || !strings.Contains(string(data), "CapEff:\t0000000000000000") {
		return errors.New("sandbox-no-new-privs-seccomp-or-capability-drop-not-enforced")
	}
	return nil
}
