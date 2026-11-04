//go:build !linux

package main

// No portable, authoritative kernel process RSS data on this platform; the
// RemoteControl status omits it rather than publishing fabricated zeroes.
func hostProcessTelemetry0419(pid int, identity string) map[string]any { return nil }
