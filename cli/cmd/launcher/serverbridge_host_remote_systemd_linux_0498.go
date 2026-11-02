//go:build linux

package main

import (
	"context"
	"time"
)

// Notify readiness for the *remote HTTPS listener*, independently of the
// Minecraft child supervised by the host service.
func remoteServiceReady0498() error {
	return hostNotify02811("READY=1\nSTATUS=RemoteControl TLS listener ready")
}

func remoteServiceStopping0498() {
	_ = hostNotify02811("STOPPING=1\nSTATUS=RemoteControl draining durable operations")
}

func remoteServiceWatchdog0498(ctx context.Context) {
	interval := hostWatchdogInterval02811()
	if interval <= 0 {
		return
	}
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				// A failed notification is detected by systemd's own watchdog.
				_ = hostNotify02811("WATCHDOG=1")
			}
		}
	}()
}
