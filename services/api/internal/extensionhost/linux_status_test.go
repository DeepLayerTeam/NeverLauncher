//go:build linux && amd64

package extensionhost

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/linuxsandbox"

	"testing"
)

func TestLinuxStatusIsolatedOnlyAfterVerifiedSetup0319(t *testing.T) {
	s := &Supervisor{}
	st := &processState{state: "running", sandbox: &extensionSandbox03111{}}
	before := s.statusOf(st)
	if before.IsolationStatus == "isolated" || before.OSSandbox != "none" {
		t.Fatalf("claimed isolation without READY: %+v", before)
	}
	st.sandboxReady = true
	st.sandbox.linux = &linuxsandbox.Handle{}
	after := s.statusOf(st)
	if after.IsolationStatus != "isolated" || after.OSSandbox == "none" || after.ExecutionTrust != "os-isolated" {
		t.Fatalf("failed to surface applied isolation: %+v", after)
	}
}
