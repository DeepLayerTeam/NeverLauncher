//go:build darwin

package macossandbox

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsignedHelperAlwaysRejected(t *testing.T) {
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", "")
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "")
	if Available() == nil {
		t.Fatal("unsigned missing helper accepted")
	}
}
func TestWrongTeamIDRejected(t *testing.T) {
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "NOT-A-TEAM")
	if _, err := teamID(); err == nil {
		t.Fatal("invalid team ID accepted")
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "ABCDEFG123")
	if _, err := teamID(); err != nil {
		t.Fatal(err)
	}
}
func TestUntrustedHelperFileRejectedBeforeCodesign(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "helper")
	if err := os.WriteFile(p, []byte("not-code"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", p)
	if _, err := helperPath(); err == nil {
		t.Fatal("group/world writable helper accepted")
	}
	if err := os.Chmod(p, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "ABCDEFG123")
	if Available() == nil {
		t.Fatal("unsigned executable accepted")
	}
}

func TestUnsupportedMacOSResourcePolicyRefusedBeforeExecution04311(t *testing.T) {
	// A valid signature cannot turn a multi-process policy into OS-enforced
	// cgroup-like isolation. Unsupported resource models are always rejected.
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", "")
	_, err := Prepare(Options{Policy: Policy{MaxMemoryBytes: 256 << 20, MaxProcesses: 4, MaxCPUPercent: 50, TimeoutSeconds: 60}, HostHandler: http.NotFoundHandler(), HostURL: "http://127.0.0.1:3000"})
	if err == nil {
		t.Fatal("unsupported multi-process macOS sandbox accepted")
	}
	if !strings.Contains(err.Error(), "helper") { // Missing helper is itself fail-closed.
		t.Fatalf("unexpected error for unsigned isolated mode: %v", err)
	}
}

func TestWritableDirectoryCannotHostTrustedHelper04311(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "NeverExtensionSandbox")
	if err := os.WriteFile(file, []byte("not signed"), 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", file)
	if _, err := helperPath(); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}
