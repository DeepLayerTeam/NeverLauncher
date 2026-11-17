//go:build linux

package devtools

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
)

// sandboxNoNetworkFilter installs a classic seccomp-BPF filter through
// bubblewrap's --seccomp FD argument. The filter rejects socket creation and
// connect on the current architecture. Unrecognised architectures are killed,
// not silently granted networking.
func sandboxNoNetworkFilter() (*os.File, error) {
	var arch uint32
	var socket, connect uint32
	switch runtime.GOARCH {
	case "amd64":
		arch, socket, connect = 0xc000003e, 41, 42 // AUDIT_ARCH_X86_64
	case "arm64":
		arch, socket, connect = 0xc00000b7, 198, 203 // AUDIT_ARCH_AARCH64
	default:
		return nil, errors.New("seccomp network policy unsupported on " + runtime.GOARCH)
	}
	type instruction struct {
		Code   uint16
		JT, JF uint8
		K      uint32
	}
	// Offsets in struct seccomp_data: nr=0, arch=4.
	// LD arch; JEQ arch; KILL; LD nr; JEQ socket; ERRNO; JEQ connect; ERRNO; ALLOW.
	ops := []instruction{
		{0x20, 0, 0, 4},
		{0x15, 1, 0, arch},
		{0x06, 0, 0, 0x80000000}, // SECCOMP_RET_KILL_PROCESS
		{0x20, 0, 0, 0},
		{0x15, 0, 1, socket},
		{0x06, 0, 0, 0x00050001}, // SECCOMP_RET_ERRNO | EPERM
		{0x15, 0, 1, connect},
		{0x06, 0, 0, 0x00050001},
		{0x06, 0, 0, 0x7fff0000}, // SECCOMP_RET_ALLOW
	}
	file, err := os.CreateTemp("", "launcher-devtools-seccomp-*")
	if err != nil {
		return nil, err
	}
	if err = file.Chmod(0600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	for _, inst := range ops {
		if err = binary.Write(file, binary.LittleEndian, inst); err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
	}
	if _, err = file.Seek(0, 0); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}
