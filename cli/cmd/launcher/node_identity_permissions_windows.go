//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Windows не раскрывает действующие права DACL через FileMode.Perm().
// Ограничивайте реальный ACL NTFS вместо приравнивания 0666 к 0600.
func windowsIdentityACL0199(path, script string) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LAUNCHER_IDENTITY_ACL_PATH="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("node identity Windows ACL operation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func restrictNodeIdentityPermissions0199(path string) error {
	// /reset очищает ранее явно заданные ACE перед отключением наследования. Давайте
	// доступ к закрытому ключу только текущему пользователю Windows и SYSTEM.
	return windowsIdentityACL0199(path, `
$ErrorActionPreference = 'Stop'
$p = $env:LAUNCHER_IDENTITY_ACL_PATH
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $p /reset | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls /reset failed' }
& icacls.exe $p /inheritance:r | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls /inheritance:r failed' }
& icacls.exe $p /grant:r ('*' + $me + ':F') '*S-1-5-18:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls /grant:r failed' }
`)
}

func verifyNodeIdentityPermissions0199(path string, _ os.FileInfo) error {
	// Проверяйте защищённый DACL и отклоняйте разрешающие или запрещающие правила для
	// всех субъектов, кроме текущего пользователя и LocalSystem. Это также выявляет
	// унаследованные разрешения Users/Everyone/Authenticated Users, которые chmod не видит.
	return windowsIdentityACL0199(path, `
$ErrorActionPreference = 'Stop'
$p = $env:LAUNCHER_IDENTITY_ACL_PATH
$acl = Get-Acl -LiteralPath $p
if (-not $acl.AreAccessRulesProtected) { throw 'node identity inherits ACL entries' }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($me, 'S-1-5-18')
$ownerRule = $false
foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $sid) { throw ('node identity ACL contains another principal: ' + $sid) }
    if ($sid -eq $me -and $rule.AccessControlType -eq 'Allow') { $ownerRule = $true }
}
if (-not $ownerRule) { throw 'node identity ACL does not grant access to current user' }
`)
}
