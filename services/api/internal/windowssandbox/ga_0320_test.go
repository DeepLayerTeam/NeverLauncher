//go:build windows

package windowssandbox

import (
	"testing"
	"unsafe"
)

// The only inheritable handles supplied to a sandboxed process must be
// explicit duplicates of the standard streams, never arbitrary process state.
func TestGAInheritedHandlesWhitelisted0320(t *testing.T) {
	streams, err := inheritableStandardHandles()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, h := range streams {
			closeHandle(h)
		}
	}()
	seen := make(map[uintptr]bool)
	for _, h := range streams {
		if h == 0 || seen[h] {
			t.Fatalf("invalid/duplicate duplicated handle: %#x", h)
		}
		seen[h] = true
		var flags uint32
		proc := kernel32.NewProc("GetHandleInformation")
		ok, _, e := proc.Call(h, uintptr(unsafe.Pointer(&flags)))
		if err := winerr("GetHandleInformation", ok, e); err != nil {
			t.Fatal(err)
		}
		if flags&1 == 0 {
			t.Fatal("standard stream duplicate is not inheritable")
		}
	}
}
