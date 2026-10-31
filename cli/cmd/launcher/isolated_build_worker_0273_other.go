//go:build !linux && !darwin && !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// On non-Linux platforms the worker still has a separate PID, bounded heap,
// wall-clock deadline, sanitized env and bounded logs. Kernel rlimits and
// process-group teardown require OS-specific runners and are not claimed.
func limitWorkerResources0273(seconds int) error { return nil }
func prepareWorkerProcess0273(cmd *exec.Cmd)     {}
func terminateWorkerTree0273(p *os.Process) {
	if p != nil {
		_ = p.Kill()
	}
}

func strictSandboxJavaCommand0273(_ context.Context, _ processorWorkerRequest0273, _ []string) (*exec.Cmd, error) {
	return nil, errors.New("strict processor sandbox requires Linux bubblewrap")
}
