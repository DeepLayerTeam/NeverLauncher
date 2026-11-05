//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Временные тики старта процесса в ядре Linux вместе с boot ID исключают путаницу при повторном использовании PID и перезагрузке.
func hostProcessIdentity0282(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("Некорректное значение: PID")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end == -1 {
		return "", fmt.Errorf("Некорректное значение: «proc stat»")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", fmt.Errorf("Процесс завершён или недействителен")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(boot)) + ":" + strconv.FormatUint(start, 10), nil
}
