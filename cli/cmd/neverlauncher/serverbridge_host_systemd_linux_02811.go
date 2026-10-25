//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The systemd notification socket may be a Linux abstract Unix socket (@name).
// No external sd_notify binary, subprocess, or libsystemd dependency is needed.
func hostNotify02811(message string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") {
		return fmt.Errorf("invalid NOTIFY_SOCKET")
	}
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(message))
	return err
}

func hostWatchdogInterval02811() time.Duration {
	value := os.Getenv("WATCHDOG_USEC")
	pid := os.Getenv("WATCHDOG_PID")
	if pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	duration := time.Duration(n) * time.Microsecond
	if duration < time.Second {
		return 0
	}
	interval := duration / 3
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	return interval
}

func hostServiceReady02811(state serverBridgeHostRuntime01910) {
	_ = hostNotify02811(fmt.Sprintf("READY=1\nSTATUS=running Minecraft pid=%d", state.ProcessPID))
}
func hostServiceStopping02811() {
	_ = hostNotify02811("STOPPING=1\nSTATUS=gracefully stopping Minecraft")
}
func hostServiceStatus02811(status string) { _ = hostNotify02811("STATUS=" + status) }

// A systemd SIGTERM is translated to the same session-bound stop request as
// `nl server-bridge host stop`; the child must receive Minecraft's console
// "stop" before OS termination. KillMode=mixed gives the supervisor time to do it.
func hostServiceRun02811(paths map[string]string, session string) func() {
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-signals:
				hostServiceStopping02811()
				// A signal can arrive before the JVM has reached running state.
				// Wait for the session's own verified child rather than sending
				// a signal to a PID obtained from stale runtime.json.
				ticker := time.NewTicker(25 * time.Millisecond)
				deadline := time.NewTimer(20 * time.Second)
				pending := true
				for pending {
					select {
					case <-done:
						pending = false
					case <-deadline.C:
						pending = false
					case <-ticker.C:
						st, err := readServerBridgeHostRuntime01910(paths["runtime"])
						if err != nil || st.SessionID != session {
							continue
						}
						if st.ProcessPID == 0 && st.Status == "restarting" {
							_ = atomicWriteJSON01910(paths["stop"], hostStopRequest0282{SessionID: session, RequestedAt: time.Now().UTC().Format(time.RFC3339Nano)}, 0600)
							pending = false
						} else if st.ProcessPID > 0 && hostIdentityMatches0282(st.ProcessPID, st.ProcessIdentity) {
							_ = atomicWriteJSON01910(paths["stop"], hostStopRequest0282{SessionID: session, ProcessPID: st.ProcessPID, RequestedAt: time.Now().UTC().Format(time.RFC3339Nano)}, 0600)
							pending = false
						}
					}
				}
				ticker.Stop()
				if !deadline.Stop() {
					select {
					case <-deadline.C:
					default:
					}
				}
			}
		}
	}()
	if interval := hostWatchdogInterval02811(); interval > 0 {
		go func() {
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					st, err := readServerBridgeHostRuntime01910(paths["runtime"])
					if err != nil || st.SessionID != session || st.SupervisorPID != os.Getpid() || !hostIdentityMatches0282(st.SupervisorPID, st.SupervisorIdentity) {
						continue
					}
					// Do not claim health if a recorded child was replaced or died.
					if st.Status == "running" && hostIdentityMatches0282(st.ProcessPID, st.ProcessIdentity) {
						_ = hostNotify02811("WATCHDOG=1")
					}
					if st.Status == "restarting" && st.ProcessPID == 0 {
						_ = hostNotify02811("WATCHDOG=1")
					}
				}
			}
		}()
	}
	return func() { close(done); signal.Stop(signals) }
}
