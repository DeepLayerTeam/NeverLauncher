//go:build windows

package privatefile

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows does not expose NTFS ACLs through FileMode.Perm. Require an
// owner-controlled DACL with access restricted to the service identity, SYSTEM
// and local administrators (who already have authority over the machine).
func Check(path string, info os.FileInfo, _ os.FileMode) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		if sid == nil || !sid.IsValid() {
			return false
		}
		value := sid.String()
		return value == user.User.Sid.String() || value == "S-1-5-18" || value == "S-1-5-32-544"
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return false
		}
		// Do not interpret unrecognized object/callback ACE layouts as ordinary ACEs.
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Restrict installs an explicit, inheritable DACL for a newly created private
// directory (or an explicit DACL for a file). Never use chmod to simulate ACLs.
func Restrict(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
