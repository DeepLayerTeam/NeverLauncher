package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Windows does not expose executable mode bits; require an actual .exe, not
// an implicitly resolved executable or a script passed through a shell.
func rehearsalExecutable(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Ext(path), ".exe")
	}
	return info.Mode().Perm()&0111 != 0
}

func rehearsalProbePath(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return "probes/" + name
}

func rehearsalProcessEnvironment(root string) []string {
	if runtime.GOOS == "windows" {
		// Do not inherit operator credentials or an untrusted PATH. Windows
		// loader and native runtime require SystemRoot.
		systemRoot := os.Getenv("SystemRoot")
		return []string{"SystemRoot=" + systemRoot, "PATH=" + filepath.Join(systemRoot, "System32"), "HOME=" + root, "USERPROFILE=" + root}
	}
	return []string{"PATH=/usr/bin:/bin", "HOME=" + root}
}
