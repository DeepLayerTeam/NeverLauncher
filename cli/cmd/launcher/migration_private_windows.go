//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Supply the protected DACL at creation time. chmod on Windows does not
// change ACLs, and writing secrets before restricting inheritance is unsafe.
func createMigrationPrivateFile(path string) (*os.File, error) {
	fail := func(err error) (*os.File, error) {
		return nil, &os.PathError{Op: "create private", Path: path, Err: err}
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fail(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fail(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return fail(err)
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")")
	if err != nil {
		return fail(err)
	}
	convert := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	localFree := syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
	var descriptor uintptr
	ok, _, callErr := convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	runtime.KeepAlive(sddl)
	if ok == 0 {
		return fail(callErr)
	}
	defer localFree.Call(descriptor)
	attrs := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fail(err)
	}
	if !strings.HasPrefix(absolute, `\\?\`) {
		if strings.HasPrefix(absolute, `\\`) {
			absolute = `\\?\UNC\` + absolute[2:]
		} else {
			absolute = `\\?\` + absolute
		}
	}
	name, err := syscall.UTF16PtrFromString(absolute)
	if err != nil {
		return fail(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, &attrs, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fail(err)
	}
	return os.NewFile(uintptr(handle), path), nil
}
