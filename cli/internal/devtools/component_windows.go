//go:build windows

package devtools

import "os/exec"

// Windows direct-child termination is provided by CommandContext. It is not a job-object sandbox.
func prepareComponentGroup(cmd *exec.Cmd) {}
func killComponentTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
