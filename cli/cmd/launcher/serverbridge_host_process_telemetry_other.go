//go:build !linux

package main

// На этой платформе нет переносимых достоверных данных ядра о RSS процесса; статус
// RemoteControl не показывает их вместо поддельных нулей.
func hostProcessTelemetry0419(pid int, identity string) map[string]any { return nil }
