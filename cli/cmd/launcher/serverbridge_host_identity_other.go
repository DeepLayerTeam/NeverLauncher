//go:build !linux && !windows

package main

import "errors"

// Platforms without a kernel-backed process birth stamp fail closed: a PID is
// not sufficient proof of identity and cannot authorize a stop/restart.
func hostProcessIdentity0282(pid int) (string, error) {
	return "", errors.New("process identity verification is unavailable on this platform")
}
