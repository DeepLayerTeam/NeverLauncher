//go:build !linux

package main

import "errors"

func hostServiceHandle02811(_ []string) error {
	return errors.New("systemd service installer is supported on Linux only")
}
