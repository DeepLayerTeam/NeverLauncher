//go:build windows

package discordrpc

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type windowsTestListener struct {
	pipes []*windowsPipe
	next  int
	mu    sync.Mutex
}

func (l *windowsTestListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range l.pipes[l.next:] {
		_ = p.Close()
	}
	l.next = len(l.pipes)
	return nil
}
func (l *windowsTestListener) Accept() (testIPCConn, error) {
	l.mu.Lock()
	if l.next >= len(l.pipes) {
		l.mu.Unlock()
		return nil, fmt.Errorf("no more pipe instances")
	}
	p := l.pipes[l.next]
	l.next++
	l.mu.Unlock()
	p.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := p.operation(func(o *syscall.Overlapped, _ *uint32) error {
		ok, _, err := pipeKernel.NewProc("ConnectNamedPipe").Call(uintptr(p.handle), uintptr(unsafe.Pointer(o)))
		if ok != 0 || err == syscall.Errno(535) {
			return nil
		}
		return err
	})
	if err != nil {
		p.Close()
		return nil, err
	}
	return testWindowsPipe{p}, nil
}

type testWindowsPipe struct{ *windowsPipe }

func (p testWindowsPipe) Close() error {
	// Ensure the final response is delivered before the server handle is closed.
	_ = syscall.FlushFileBuffers(p.handle)
	return p.windowsPipe.Close()
}
func newTestIPCListener(t *testing.T, count int) (testIPCListener, []string) {
	t.Helper()
	path := fmt.Sprintf(`\\.\pipe\nl-discord-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	paths := make([]string, 0, count)
	l := &windowsTestListener{}
	t.Cleanup(func() { l.Close() })
	for i := 0; i < count; i++ {
		namePath := fmt.Sprintf("%s-%d", path, i)
		name, err := syscall.UTF16PtrFromString(namePath)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, namePath)
		// duplex, overlapped, byte stream, reject remote clients.
		h, _, err := pipeKernel.NewProc("CreateNamedPipeW").Call(uintptr(unsafe.Pointer(name)), 3|syscall.FILE_FLAG_OVERLAPPED, 8, 1, 65536, 65536, 0, 0)
		if syscall.Handle(h) == syscall.InvalidHandle {
			t.Fatal(err)
		}
		l.pipes = append(l.pipes, &windowsPipe{handle: syscall.Handle(h)})
	}
	return l, paths
}
