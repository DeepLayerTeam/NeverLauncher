//go:build windows

package main

import (
	"fmt"
	"os"
)

func hostPrivateCheck(path string, info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("небезопасный путь: %s", path)
	}
	// Inherited ACEs from an explicitly protected parent are safe if their
	// actual identities are trusted. Reject all other principals and reparse points.
	return windowsIdentityACL0199(path, `
$ErrorActionPreference = 'Stop'
$p = $env:LAUNCHER_IDENTITY_ACL_PATH
if (([System.IO.File]::GetAttributes($p) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point' }
$acl = if ([System.IO.Directory]::Exists($p)) { [System.IO.Directory]::GetAccessControl($p) } else { [System.IO.File]::GetAccessControl($p) }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($me, 'S-1-5-18', 'S-1-5-32-544')
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($allowed -notcontains $owner) { throw 'Untrusted owner' }
$ownerRule = $false
foreach ($rule in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
    $sid = $rule.IdentityReference.Value
    if ($allowed -notcontains $sid) { throw ('Untrusted ACL: ' + $sid) }
    if ($sid -eq $me -and $rule.AccessControlType -eq 'Allow') { $ownerRule = $true }
}
if (-not $ownerRule) { throw 'Missing owner rule' }
`)
}
func hostPrivateRestrictDir(path string) error {
	return windowsIdentityACL0199(path, `
$ErrorActionPreference = 'Stop'
$p = $env:LAUNCHER_IDENTITY_ACL_PATH
if (([System.IO.File]::GetAttributes($p) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point' }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$acl = [System.IO.Directory]::GetAccessControl($p)
$acl.SetAccessRuleProtection($true,$false)
foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
foreach ($sid in @($me,$system)) {
 $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 $acl.AddAccessRule($rule)
}
[System.IO.Directory]::SetAccessControl($p,$acl)
`)
}
