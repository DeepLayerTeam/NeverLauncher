//go:build darwin

package main

import (
	"os"
	"testing"
)

func TestDarwinHostIdentityBirthTime(t *testing.T) {
	pid := os.Getpid()
	identity, err := hostProcessIdentity0282(pid)
	if err != nil || identity == "" {
		t.Fatalf("process identity: %q %v", identity, err)
	}
	if !hostIdentityMatches0282(pid, identity) {
		t.Fatal("current process identity mismatch")
	}
	if hostIdentityMatches0282(pid, identity+"-forged") {
		t.Fatal("forged identity accepted")
	}
	if _, err = hostProcessIdentity0282(-1); err == nil {
		t.Fatal("invalid PID accepted")
	}
}
