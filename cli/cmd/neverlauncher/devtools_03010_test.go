package main

import (
	"os"
	"strings"
	"testing"
)

func TestDevTools03010PolicyDenied(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_DEVTOOLS_TEST_MODE", "")
	for _, args := range [][]string{
		{"auth", "serve", "--ack-test-only", "--duration", "1s"},
		{"component", "test", "--jar", "test.jar", "--isolation", "process"},
	} {
		if e := handleDevTools03010(args); e == nil {
			t.Fatalf("unrestricted test command accepted: %v", args)
		}
	}
}
func TestDevTools03010NoNetworkOnInvalidInput(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_DEVTOOLS_TEST_MODE", "1")
	err := handleDevTools03010([]string{"auth", "serve", "--ack-test-only", "--listen", "0.0.0.0:0", "--duration", "2s"})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected refusal of public bind: %v", err)
	}
	if e := handleDevTools03010([]string{"jar", "strip-debug", "--input", "missing.jar", "--output", os.DevNull}); e == nil {
		t.Fatal("missing JAR accepted")
	}
}
