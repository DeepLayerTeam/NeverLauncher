//go:build windows

package main

import "os"

func worldBackupVerifyPrivateDir02810(path string, fi os.FileInfo) error {
	// Windows FileMode does not represent NTFS ACLs. Restrict the backup tree
	// to the current user and SYSTEM, including newly created descendants.
	if err := windowsIdentityACL0199(path, `
$ErrorActionPreference = 'Stop'
$p = $env:LAUNCHER_IDENTITY_ACL_PATH
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$acl = [System.IO.Directory]::GetAccessControl($p)
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
foreach ($sid in @($me, $system)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
[System.IO.Directory]::SetAccessControl($p, $acl)
`); err != nil {
		return err
	}
	return verifyNodeIdentityPermissions0199(path, fi)
}
