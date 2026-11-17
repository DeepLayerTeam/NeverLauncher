//go:build linux

package devtools

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"testing"
)

// The fallback is only safe when both socket creation and connections are
// rejected by the kernel; never silently grant the host network to a JAR.
func TestSandboxNoNetworkFilter(t *testing.T) {
	f, err := sandboxNoNetworkFilter()
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 9*8 {
		t.Fatalf("unexpected seccomp BPF length: %d", len(raw))
	}
	get := func(i int) (uint16, uint8, uint8, uint32) {
		b := raw[i*8 : (i+1)*8]
		return binary.LittleEndian.Uint16(b), b[2], b[3], binary.LittleEndian.Uint32(b[4:])
	}
	load, _, _, offset := get(0)
	if load != 0x20 || offset != 4 {
		t.Fatal("filter does not validate audit architecture")
	}
	code, jt, jf, arch := get(1)
	if code != 0x15 || jt != 1 || jf != 0 {
		t.Fatal("architecture is not enforced")
	}
	_, _, _, action := get(2)
	if action != 0x80000000 {
		t.Fatal("unknown architectures must fail closed")
	}
	_, _, _, off := get(3)
	if off != 0 {
		t.Fatal("syscall number offset is wrong")
	}
	_, _, _, socket := get(4)
	_, _, _, socketDenied := get(5)
	_, _, _, connect := get(6)
	_, _, _, connectDenied := get(7)
	_, _, _, allowed := get(8)
	if socketDenied != 0x00050001 || connectDenied != 0x00050001 || allowed != 0x7fff0000 {
		t.Fatal("network isolation policy is incomplete")
	}
	switch runtime.GOARCH {
	case "amd64":
		if arch != 0xc000003e || socket != 41 || connect != 42 {
			t.Fatal("unexpected amd64 seccomp syscalls")
		}
	case "arm64":
		if arch != 0xc00000b7 || socket != 198 || connect != 203 {
			t.Fatal("unexpected arm64 seccomp syscalls")
		}
	default:
		t.Fatal("unexpected architecture accepted")
	}
}
