//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestRemoteSystemdGivesDrainWindow0428(t *testing.T) {
	unit, err := hostServiceUnit02811(hostServiceSpec02811{Name: "remote", Root: "/srv/game", Binary: "/usr/local/bin/nl", Scope: "user", Component: "remote", TLSCert: "/tmp/remote.pem", TLSKey: "/tmp/remote.key", Listen: "127.0.0.1:9443", StopSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, "TimeoutStopSec=105s") || !strings.Contains(unit, "KillMode=process") {
		t.Fatalf("remote shutdown not safe: %s", unit)
	}
}
