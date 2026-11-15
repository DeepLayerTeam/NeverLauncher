//go:build windows

package discordrpc

import (
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var pipeKernel = syscall.NewLazyDLL("kernel32.dll")
var pipeCreateEvent = pipeKernel.NewProc("CreateEventW")
var pipeGetResult = pipeKernel.NewProc("GetOverlappedResult")

// Use overlapped I/O instead of os.File's synchronous pipe handles, which do
// not support SetDeadline on Windows. A timed-out operation is cancelled and
// drained before its buffer or OVERLAPPED can go out of scope.
type windowsPipe struct {
	handle   syscall.Handle
	deadline time.Time
}

func openWindowsPipe(path string) (io.ReadWriteCloser, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prevents the pipe server
	// from impersonating the launcher as a privileged client.
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OVERLAPPED|0x00100000|0x00010000, 0)
	if err != nil {
		return nil, err
	}
	return &windowsPipe{handle: h}, nil
}
func (p *windowsPipe) Close() error                  { return syscall.CloseHandle(p.handle) }
func (p *windowsPipe) SetDeadline(d time.Time) error { p.deadline = d; return nil }
func (p *windowsPipe) Read(b []byte) (int, error)    { return p.transfer(b, false) }
func (p *windowsPipe) Write(b []byte) (int, error)   { return p.transfer(b, true) }
func (p *windowsPipe) transfer(b []byte, write bool) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var pin runtime.Pinner
	pin.Pin(&b[0])
	defer pin.Unpin()
	n, err := p.operation(func(o *syscall.Overlapped, n *uint32) error {
		if write {
			return syscall.WriteFile(p.handle, b, n, o)
		}
		return syscall.ReadFile(p.handle, b, n, o)
	})
	if errors.Is(err, syscall.ERROR_BROKEN_PIPE) || errors.Is(err, syscall.Errno(232)) || errors.Is(err, syscall.Errno(233)) {
		if write {
			return n, ErrDisconnected
		}
		return n, io.EOF
	}
	if !write && n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}
func (p *windowsPipe) operation(start func(*syscall.Overlapped, *uint32) error) (int, error) {
	remaining := time.Until(p.deadline)
	if p.deadline.IsZero() {
		remaining = 5 * time.Second
	}
	if remaining <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	event, _, err := pipeCreateEvent.Call(0, 1, 0, 0)
	if event == 0 {
		return 0, err
	}
	defer syscall.CloseHandle(syscall.Handle(event))
	o := syscall.Overlapped{HEvent: syscall.Handle(event)}
	var n uint32
	var pin runtime.Pinner
	pin.Pin(&o)
	pin.Pin(&n)
	defer pin.Unpin()
	err = start(&o, &n)
	if err == nil {
		return int(n), nil
	}
	if !errors.Is(err, syscall.ERROR_IO_PENDING) {
		return 0, err
	}
	wait := uint32(min(remaining/time.Millisecond+1, time.Duration(0xfffffffe)))
	result, waitErr := syscall.WaitForSingleObject(o.HEvent, wait)
	if waitErr != nil || result != syscall.WAIT_OBJECT_0 {
		_ = syscall.CancelIoEx(p.handle, &o)
		// GetOverlappedResult(TRUE) waits for cancellation/completion.
		pipeGetResult.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&o)), uintptr(unsafe.Pointer(&n)), 1)
		if waitErr != nil {
			return 0, waitErr
		}
		return 0, os.ErrDeadlineExceeded
	}
	ok, _, err := pipeGetResult.Call(uintptr(p.handle), uintptr(unsafe.Pointer(&o)), uintptr(unsafe.Pointer(&n)), 0)
	if ok == 0 {
		return int(n), err
	}
	return int(n), nil
}
