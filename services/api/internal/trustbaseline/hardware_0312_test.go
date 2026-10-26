package trustbaseline

import (
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestHardwareCertifyAssessmentPreservesGuardGate0312(t *testing.T) {
	now := time.Now().UTC()
	d := testDevice0311(now)
	d.UserID = "owner"
	d.ID = "device"
	d.KeyFingerprint = strings.Repeat("e", 64)
	v := model.DeviceHardwareEvidence{UserID: d.UserID, DeviceID: d.ID, SessionID: "session", BindingEpoch: 3, KeyFingerprint: d.KeyFingerprint, AKFingerprint: strings.Repeat("a", 64), RootID: "operator-ca", RootFingerprint: strings.Repeat("b", 64), VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	a := EvaluateWithHardwareEvidence(d, true, v, now)
	if a.RemoteHardwareProvenance != "tpm-ak-certified" || a.ProfileDecisions[Strict].Result != Deny || a.ProfileDecisions[Standard].Result != Allow || contains0311(a.ReasonCodes, "remote-hardware-verifier-unavailable") || !contains0311(a.ReasonCodes, "guard-runtime-evidence-unavailable") {
		t.Fatalf("incorrect attestation assessment %+v", a)
	}
	for _, tc := range []struct {
		name   string
		change func(*model.DeviceHardwareEvidence)
		bound  bool
	}{
		{"foreign key", func(e *model.DeviceHardwareEvidence) { e.KeyFingerprint = "wrong" }, true},
		{"foreign device", func(e *model.DeviceHardwareEvidence) { e.DeviceID = "foreign" }, true},
		{"foreign user", func(e *model.DeviceHardwareEvidence) { e.UserID = "foreign" }, true},
		{"expired", func(e *model.DeviceHardwareEvidence) { e.ExpiresAt = now.Add(-time.Second) }, true},
		{"future", func(e *model.DeviceHardwareEvidence) { e.VerifiedAt = now.Add(time.Second) }, true},
		{"session unbound", func(e *model.DeviceHardwareEvidence) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := v
			tc.change(&e)
			a := EvaluateWithHardwareEvidence(d, tc.bound, e, now)
			if a.RemoteHardwareProvenance != "not-verified" || a.ProfileDecisions[Strict].Result != Deny {
				t.Fatalf("forged assurance: %+v", a)
			}
		})
	}
}
