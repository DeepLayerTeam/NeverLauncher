//go:build windows

package installer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func writeWindowsShortcut(path, target, config, root string) error {
	if err := secureDir(filepath.Dir(path)); err != nil {
		return err
	}
	// Values are passed as environment variables, never interpolated in script.
	script := `$lnk=(New-Object -ComObject WScript.Shell).CreateShortcut($env:NL_LINK);$lnk.TargetPath=$env:NL_TARGET;$lnk.Arguments='--config "'+$env:NL_CONFIG+'" --root "'+$env:NL_ROOT+'"';$lnk.WorkingDirectory=[IO.Path]::GetDirectoryName($env:NL_TARGET);$lnk.Save()`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "NL_LINK="+path, "NL_TARGET="+target, "NL_CONFIG="+config, "NL_ROOT="+root)
	return cmd.Run()
}
func removeWindowsShortcut(path, managedRoot string) error {
	_, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	script := `$lnk=(New-Object -ComObject WScript.Shell).CreateShortcut($env:NL_LINK);[Console]::Write($lnk.TargetPath)`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "NL_LINK="+path)
	data, e := cmd.Output()
	if e != nil {
		return e
	}
	target := filepath.Clean(string(data))
	rel, e := filepath.Rel(managedRoot, target)
	if e != nil {
		return e
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("refusing to delete user-modified Windows shortcut")
	}
	return os.Remove(path)
}
