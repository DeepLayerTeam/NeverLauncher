//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// hostProcessTelemetry0419 reads kernel process/host counters only after the
// existing PID+start-identity check. Reverify identity after reading to prevent
// a recycled PID from masquerading as the managed JVM.
func hostProcessTelemetry0419(pid int, identity string) map[string]any {
	if pid <= 0 || identity == "" || !hostIdentityMatches0282(pid, identity) {
		return nil
	}
	result := map[string]any{"processId": pid}
	if raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "statm")); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 2 {
			if residentPages, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil && residentPages <= 1<<50 {
				result["processResidentBytes"] = residentPages * uint64(os.Getpagesize())
			}
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[2] != "kB" {
				continue
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || v > 1<<50 {
				continue
			}
			switch fields[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				available = v * 1024
			}
		}
		if total > 0 && available <= total {
			result["hostTotalMemoryBytes"] = total
			result["hostAvailableMemoryBytes"] = available
		}
	}
	if !hostIdentityMatches0282(pid, identity) {
		return nil
	}
	return result
}
