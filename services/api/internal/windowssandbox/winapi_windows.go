//go:build windows

package windowssandbox

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	userenv             = syscall.NewLazyDLL("userenv.dll")
	advapi              = syscall.NewLazyDLL("advapi32.dll")
	createProfile       = userenv.NewProc("CreateAppContainerProfile")
	deriveSID           = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	deleteProfile       = userenv.NewProc("DeleteAppContainerProfile")
	getProfilePath      = userenv.NewProc("GetAppContainerFolderPath")
	localFree           = kernel32.NewProc("LocalFree")
	initAttrs           = kernel32.NewProc("InitializeProcThreadAttributeList")
	updateAttrs         = kernel32.NewProc("UpdateProcThreadAttribute")
	deleteAttrs         = kernel32.NewProc("DeleteProcThreadAttributeList")
	createProc          = kernel32.NewProc("CreateProcessW")
	createJob           = kernel32.NewProc("CreateJobObjectW")
	setJob              = kernel32.NewProc("SetInformationJobObject")
	assignJob           = kernel32.NewProc("AssignProcessToJobObject")
	resumeThread        = kernel32.NewProc("ResumeThread")
	waitObject          = kernel32.NewProc("WaitForSingleObject")
	getExitCode         = kernel32.NewProc("GetExitCodeProcess")
	terminateJob        = kernel32.NewProc("TerminateJobObject")
	createNamedPipe     = kernel32.NewProc("CreateNamedPipeW")
	connectNamedPipe    = kernel32.NewProc("ConnectNamedPipe")
	disconnectNamedPipe = kernel32.NewProc("DisconnectNamedPipe")
	convertSDDL         = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getLengthSD         = advapi.NewProc("GetSecurityDescriptorLength")
	convertSID          = advapi.NewProc("ConvertSidToStringSidW")
	openProcessToken    = advapi.NewProc("OpenProcessToken")
	getTokenInformation = advapi.NewProc("GetTokenInformation")
	equalSID            = advapi.NewProc("EqualSid")
	terminateProcess    = kernel32.NewProc("TerminateProcess")
)

func winerr(op string, r uintptr, e error) error {
	if r != 0 {
		return nil
	}
	if e != nil && e != syscall.Errno(0) {
		return fmt.Errorf("%s: %w", op, e)
	}
	return fmt.Errorf("%s failed", op)
}
func utf16FromPtr(p *uint16) string {
	if p == nil {
		return ""
	}
	buf := []uint16{}
	for i := uintptr(0); i < 32768; i++ {
		v := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2*i))
		if v == 0 {
			break
		}
		buf = append(buf, v)
	}
	return syscall.UTF16ToString(buf)
}
func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }
func newProfile(name string) (uintptr, string, error) {
	n := utf16(name)
	var sid uintptr
	r, _, _ := createProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	// HRESULT ERROR_ALREADY_EXISTS = 0x800700b7. Only the randomized caller name can reuse an existing profile.
	if r == 0x800700b7 {
		r, _, _ = deriveSID.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid)))
	}
	if r != 0 || sid == 0 {
		return 0, "", fmt.Errorf("CreateAppContainerProfile/Derive SID: HRESULT 0x%x", r)
	}
	var p *uint16
	ok, _, err := convertSID.Call(sid, uintptr(unsafe.Pointer(&p)))
	if e := winerr("ConvertSidToStringSid", ok, err); e != nil {
		localFree.Call(sid)
		return 0, "", e
	}
	s := utf16FromPtr(p)
	localFree.Call(uintptr(unsafe.Pointer(p)))
	return sid, s, nil
}
func destroyProfile(name string) { deleteProfile.Call(uintptr(unsafe.Pointer(utf16(name)))) }
func freeSID(sid uintptr) {
	if sid != 0 {
		localFree.Call(sid)
	}
}
func profilePath(sid uintptr) (string, error) {
	var p *uint16
	r, _, _ := getProfilePath.Call(sid, uintptr(unsafe.Pointer(&p)))
	if r != 0 || p == nil {
		return "", fmt.Errorf("GetAppContainerFolderPath: HRESULT 0x%x", r)
	}
	result := utf16FromPtr(p)
	localFree.Call(uintptr(unsafe.Pointer(p)))
	return result, nil
}
func securityDescriptor(sddl string) (uintptr, error) {
	var sd uintptr
	r, _, e := convertSDDL.Call(uintptr(unsafe.Pointer(utf16(sddl))), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if err := winerr("ConvertStringSecurityDescriptorToSecurityDescriptor", r, e); err != nil {
		return 0, err
	}
	return sd, nil
}
func closeHandle(h uintptr) {
	if h != 0 && h != ^uintptr(0) {
		syscall.CloseHandle(syscall.Handle(h))
	}
}
func ensureWindows() error {
	if os.Getenv("OS") != "Windows_NT" {
		return errors.New("windows-process-environment-unavailable")
	}
	return nil
}
func validSID(s string) bool { return strings.HasPrefix(s, "S-1-15-2-") && len(s) < 300 }

type securityCapabilities struct {
	appContainerSid uintptr
	capabilities    uintptr
	capabilityCount uint32
	reserved        uint32
}
type startupInfo struct {
	cb                                                                 uint32
	reserved                                                           uintptr
	desktop                                                            uintptr
	title                                                              uintptr
	x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags uint32
	showWindow, reserved2                                              uint16
	reserved2Ptr                                                       uintptr
	stdInput, stdOutput, stdError                                      uintptr
}
type startupInfoEx struct {
	startupInfo
	attrList uintptr
}
type processInfo struct {
	process, thread     uintptr
	processId, threadId uint32
}

const (
	procThreadSecurityCapabilities = 0x00020009
	extendedStartupInfo            = 0x00080000
	createSuspended                = 0x00000004
	createUnicodeEnvironment       = 0x00000400
	startfUseStdHandles            = 0x00000100
	waitInfinite                   = 0xFFFFFFFF
	jobExtendedLimitInformation    = 9
	jobCPURateControlInformation   = 15
	jobKillOnClose                 = 0x2000
	jobProcessMemory               = 0x100
	jobActiveProcesses             = 0x8
	jobCPURateEnable               = 0x1
	jobCPURateHardCap              = 0x4
)

type ioCounters struct{ readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes uint64 }
type basicLimit struct {
	perProcessUserTime, perJobUserTime int64
	limitFlags                         uint32
	minWorkingSet, maxWorkingSet       uintptr
	activeProcessLimit                 uint32
	affinity                           uintptr
	priorityClass, schedulingClass     uint32
}
type extendedLimits struct {
	basic                                                                        basicLimit
	io                                                                           ioCounters
	processMemoryLimit, jobMemoryLimit, peakProcessMemoryUsed, peakJobMemoryUsed uintptr
}
type cpuRate struct{ control, rate uint32 }

// AppContainer process creation is verified against the actual primary token,
// not just a successful UpdateProcThreadAttribute call.
func verifyAppContainerToken(process uintptr, wantSID uintptr) error {
	var token uintptr
	ok, _, e := openProcessToken.Call(process, 0x0008, uintptr(unsafe.Pointer(&token))) // TOKEN_QUERY
	if er := winerr("OpenProcessToken", ok, e); er != nil {
		return er
	}
	defer closeHandle(token)
	var isContainer uint32
	var received uint32
	ok, _, e = getTokenInformation.Call(token, 29, uintptr(unsafe.Pointer(&isContainer)), 4, uintptr(unsafe.Pointer(&received))) // TokenIsAppContainer
	if er := winerr("GetTokenInformation(TokenIsAppContainer)", ok, e); er != nil {
		return er
	}
	if isContainer != 1 {
		return errors.New("sandbox-created-process-does-not-have-AppContainer-token")
	}
	var tokenContainerSID uintptr
	ok, _, e = getTokenInformation.Call(token, 31, uintptr(unsafe.Pointer(&tokenContainerSID)), uintptr(unsafe.Sizeof(tokenContainerSID)), uintptr(unsafe.Pointer(&received))) // TokenAppContainerSid
	if er := winerr("GetTokenInformation(TokenAppContainerSid)", ok, e); er != nil {
		return er
	}
	if tokenContainerSID == 0 {
		return errors.New("sandbox-child-AppContainer-SID-is-empty")
	}
	same, _, _ := equalSID.Call(tokenContainerSID, wantSID)
	if same == 0 {
		return errors.New("sandbox-child-AppContainer-SID-mismatch")
	}
	return nil
}
func createIsolatedProcess(c childConfig, sid uintptr) (uintptr, uintptr, uintptr, uint32, error) {
	// Request a real AppContainer token through the Windows process attribute.
	// Windows will return ERROR_NOT_SUPPORTED if it cannot apply it.
	var size uintptr
	initAttrs.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, 0, 0, 0, errors.New("AppContainer attribute list unavailable")
	}
	backing := make([]byte, size)
	attrs := uintptr(unsafe.Pointer(&backing[0]))
	r, _, e := initAttrs.Call(attrs, 1, 0, uintptr(unsafe.Pointer(&size)))
	if err := winerr("InitializeProcThreadAttributeList", r, e); err != nil {
		return 0, 0, 0, 0, err
	}
	defer deleteAttrs.Call(attrs)
	sc := securityCapabilities{appContainerSid: sid}
	r, _, e = updateAttrs.Call(attrs, 0, procThreadSecurityCapabilities, uintptr(unsafe.Pointer(&sc)), unsafe.Sizeof(sc), 0, 0)
	if err := winerr("AppContainer SECURITY_CAPABILITIES", r, e); err != nil {
		return 0, 0, 0, 0, err
	}
	job, _, e := createJob.Call(0, 0)
	if err := winerr("CreateJobObject", job, e); err != nil {
		return 0, 0, 0, 0, err
	}
	fail := func(err error) (uintptr, uintptr, uintptr, uint32, error) { closeHandle(job); return 0, 0, 0, 0, err }
	limits := extendedLimits{}
	limits.basic.limitFlags = jobKillOnClose | jobProcessMemory | jobActiveProcesses
	limits.basic.activeProcessLimit = uint32(c.Policy.MaxProcesses)
	limits.processMemoryLimit = uintptr(c.Policy.MaxMemoryBytes)
	limits.jobMemoryLimit = uintptr(c.Policy.MaxMemoryBytes)
	limits.basic.limitFlags |= 0x200 // JOB_OBJECT_LIMIT_JOB_MEMORY
	r, _, e = setJob.Call(job, jobExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if err := winerr("SetInformationJobObject limits", r, e); err != nil {
		return fail(err)
	}
	cpu := cpuRate{control: jobCPURateEnable | jobCPURateHardCap, rate: uint32(c.Policy.MaxCPUPercent * 100)}
	r, _, e = setJob.Call(job, jobCPURateControlInformation, uintptr(unsafe.Pointer(&cpu)), unsafe.Sizeof(cpu))
	if err := winerr("SetInformationJobObject CPU", r, e); err != nil {
		return fail(err)
	}
	// Both cmd and its environment originate from a signed, validated extension manifest.
	args := append([]string{c.Entrypoint}, c.Args...)
	commandLine := syscall.EscapeArg(args[0])
	for _, a := range args[1:] {
		commandLine += " " + syscall.EscapeArg(a)
	}
	env := make([]string, 0, len(c.Environment)+5)
	for _, v := range c.Environment {
		k, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(k) {
		case "NEVERLAUNCHER_EXTENSION_HOST_URL", "NEVERLAUNCHER_EXTENSION_HOST_PIPE", "TEMP", "TMP", "LOCALAPPDATA":
			continue
		}
		env = append(env, v)
	}
	env = append(env, "NEVERLAUNCHER_EXTENSION_HOST_URL=http://neverlauncher.host.invalid", "NEVERLAUNCHER_EXTENSION_HOST_PIPE="+c.Pipe)
	env = append(env, "TEMP="+c.Scratch, "TMP="+c.Scratch, "LOCALAPPDATA="+c.Scratch)
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	envBlock := []uint16{}
	for _, pair := range env {
		if strings.IndexByte(pair, 0) >= 0 {
			return fail(errors.New("NUL in child environment"))
		}
		envBlock = append(envBlock, syscall.StringToUTF16(pair)...)
	}
	envBlock = append(envBlock, 0)
	si := startupInfoEx{startupInfo: startupInfo{cb: uint32(unsafe.Sizeof(startupInfoEx{})), flags: startfUseStdHandles}, attrList: attrs}
	// Only the child's standard streams are inherited; the AppContainer token prohibits
	// opening backend process handles, but handles must still be audited in deployment.
	si.stdInput = uintptr(syscall.Stdin)
	si.stdOutput = uintptr(syscall.Stdout)
	si.stdError = uintptr(syscall.Stderr)
	var pi processInfo
	r, _, e = createProc.Call(uintptr(unsafe.Pointer(utf16(c.Entrypoint))), uintptr(unsafe.Pointer(utf16(commandLine))), 0, 0, 1,
		extendedStartupInfo|createSuspended|createUnicodeEnvironment, uintptr(unsafe.Pointer(&envBlock[0])), uintptr(unsafe.Pointer(utf16(c.PayloadRoot))), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if err := winerr("CreateProcessW AppContainer", r, e); err != nil {
		return fail(err)
	}
	if err := verifyAppContainerToken(pi.process, sid); err != nil {
		terminateProcess.Call(pi.process, 1)
		closeHandle(pi.thread)
		closeHandle(pi.process)
		return fail(err)
	}
	r, _, e = assignJob.Call(job, pi.process)
	if err := winerr("AssignProcessToJobObject before resume", r, e); err != nil {
		terminateProcess.Call(pi.process, 1)
		closeHandle(pi.thread)
		closeHandle(pi.process)
		return fail(err)
	}
	// The child remains suspended until the parent has recorded its real PID.
	// The helper retains the suspended thread and Job handles until the parent
	// confirms readiness over the authenticated per-instance control pipe.
	return pi.process, pi.thread, job, pi.processId, nil
}
