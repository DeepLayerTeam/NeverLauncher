//go:build linux

package main

import (
	"context"
	"time"
)

// Сообщайте о готовности именно УДАЛЁННОГО HTTPS-прослушивателя, независимо от
// дочернего Minecraft, которым управляет супервизор службы хоста.
func remoteServiceReady0498() error {
	return hostNotify02811("READY=1\nSTATUS=Служба RemoteControl TLS готова к подключениям")
}

func remoteServiceStopping0498() {
	_ = hostNotify02811("STOPPING=1\nSTATUS=RemoteControl завершает сохраняемые операции")
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
				// Неудачу уведомления обнаружит собственный watchdog systemd.
				_ = hostNotify02811("WATCHDOG=1")
			}
		}
	}()
}
