//go:build windows

package devtools

import "os/exec"

// В Windows CommandContext завершает непосредственный дочерний процесс. Это не песочница на основе job object.
func prepareComponentGroup(cmd *exec.Cmd) {}
func killComponentTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
