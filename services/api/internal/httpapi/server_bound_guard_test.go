package httpapi

import (
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func fixtureGuardBoundSession0507(t *testing.T) (bridgeJoinRecord, *verifiedPlanEvidence02412, model.DeviceChallenge) {
	t.Helper()
	hash := func(b string) string { return strings.Repeat(b, 64) }
	j := bridgeJoinRecord{
		ID: "ticket-0507", UserID: "player-0507", SessionID: "never-session-0507",
		MinecraftSessionID: "minecraft-session-0507", TrustedDeviceID: "device-0507", BindingEpoch: 5,
		ServerID: "paper-0507", ProjectID: "project", ProfileID: "fabric", Channel: "stable", Username: "TestPlayer", UUID: "1234567890abcdef1234567890abcdef",
		IdentityRealm: "local", SessionCorrelationID: hash("a"), ProtocolVersion: 3,
	}
	p := &verifiedPlanEvidence02412{
		UserID: j.UserID, SessionID: j.SessionID, DeviceID: j.TrustedDeviceID, BindingEpoch: j.BindingEpoch, ServerID: j.ServerID,
		ProjectID: j.ProjectID, ProfileID: j.ProfileID, Channel: j.Channel, PlanSHA256: hash("b"), CatalogDigest: hash("c"), ReleaseSignature: strings.Repeat("d", 128), GuardAttestationSHA256: hash("e"),
	}
	ticket := model.DeviceChallenge{
		ID: "signed-one-use-guard-0507", UserID: j.UserID, DeviceID: j.TrustedDeviceID, CreatedAt: time.Now().UTC(),
		Metadata: map[string]any{
			"sessionId": j.SessionID, "bindingEpoch": "5", "minecraftSessionId": j.MinecraftSessionID, "deviceKeyFingerprint": hash("f"),
			"javaMajor": "21", "runtimePid": "5027", "attestationSha256": p.GuardAttestationSHA256,
			"continuousEvidenceSha256": hash("1"), "guardSha256": hash("2"), "launcherSha256": hash("3"), "launcherVersion": "0.50.7",
			"runtimePolicySha256": hash("4"), "moduleSetSha256": hash("5"), "codeSetSha256": hash("6"), "hookSetSha256": hash("7"), "jvmStateSha256": hash("8"),
		},
	}
	return j, p, ticket
}

func TestGuardBoundSession0507VerifiedIssuance(t *testing.T) {
	join, plan, ticket := fixtureGuardBoundSession0507(t)
	got, err := createGuardBoundSession0507(join, plan, ticket)
	if err != nil {
		t.Fatalf("Корректная привязка Guard ошибочно отклонена: %v", err)
	}
	if got.CorrelationID != join.SessionCorrelationID || got.PlanSHA256 != plan.PlanSHA256 || got.GuardAttestationSHA256 != plan.GuardAttestationSHA256 || got.ServerID != join.ServerID || got.SessionID != join.SessionID || got.GuardPID != 5027 {
		t.Fatalf("Привязка Guard потеряла проверенные поля личности, сборки или доказательств: %+v", got)
	}
}

func TestGuardBoundSession0507RejectsCrossSessionAndTamper(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*bridgeJoinRecord, *verifiedPlanEvidence02412, *model.DeviceChallenge)
	}{
		{"account", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.UserID = "other-user"
		}},
		{"server", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.ServerID = "other-server"
		}},
		{"project", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.ProjectID = "other-project"
		}},
		{"session", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.SessionID = "other-session"
		}},
		{"device", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.TrustedDeviceID = "other-device"
		}},
		{"epoch", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) { j.BindingEpoch++ }},
		{"minecraft-session", func(j *bridgeJoinRecord, _ *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			j.MinecraftSessionID = "other-minecraft"
		}},
		{"plan-attestation", func(_ *bridgeJoinRecord, p *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			p.GuardAttestationSHA256 = strings.Repeat("9", 64)
		}},
		{"unsigned-plan", func(_ *bridgeJoinRecord, p *verifiedPlanEvidence02412, _ *model.DeviceChallenge) {
			p.PlanSHA256 = "missing"
		}},
		{"runtime-policy", func(_ *bridgeJoinRecord, _ *verifiedPlanEvidence02412, t *model.DeviceChallenge) {
			t.Metadata["runtimePolicySha256"] = "malformed"
		}},
		{"fake-guard-pid", func(_ *bridgeJoinRecord, _ *verifiedPlanEvidence02412, t *model.DeviceChallenge) {
			t.Metadata["runtimePid"] = "0"
		}},
		{"missing-guard", func(_ *bridgeJoinRecord, _ *verifiedPlanEvidence02412, t *model.DeviceChallenge) { t.ID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j, p, ticket := fixtureGuardBoundSession0507(t)
			tc.alter(&j, p, &ticket)
			if _, err := createGuardBoundSession0507(j, p, ticket); err == nil {
				t.Fatal("Недоверенная привязка Guard ошибочно принята")
			}
		})
	}
}

func TestGuardBoundSession0507RuntimeBindingChecks(t *testing.T) {
	j, p, ticket := fixtureGuardBoundSession0507(t)
	b, err := createGuardBoundSession0507(j, p, ticket)
	if err != nil {
		t.Fatal(err)
	}
	b.LiveUserID = b.UserID
	b.LiveSessionID = b.SessionID
	b.LiveMinecraftSessionID = b.MinecraftSessionID
	b.LiveTrustedDeviceID = b.TrustedDeviceID
	b.LiveBindingEpoch = b.BindingEpoch
	b.LiveProjectID = b.ProjectID
	b.LiveProfileID = b.ProfileID
	b.LiveChannel = b.Channel
	b.LiveUsername = b.Username
	b.LiveUUID = b.PlayerUUID
	if !guardBoundLiveMatches0507(b) {
		t.Fatal("Отклонена та же подтверждённая запись игрока")
	}
	changes := []struct {
		name   string
		tamper func(*repository.GuardBoundSession0507)
	}{
		{"user", func(x *repository.GuardBoundSession0507) { x.LiveUserID = "attacker" }},
		{"session", func(x *repository.GuardBoundSession0507) { x.LiveSessionID = "attacker" }},
		{"minecraft", func(x *repository.GuardBoundSession0507) { x.LiveMinecraftSessionID = "attacker" }},
		{"device", func(x *repository.GuardBoundSession0507) { x.LiveTrustedDeviceID = "attacker" }},
		{"epoch", func(x *repository.GuardBoundSession0507) { x.LiveBindingEpoch++ }},
		{"project", func(x *repository.GuardBoundSession0507) { x.LiveProjectID = "attacker" }},
		{"profile", func(x *repository.GuardBoundSession0507) { x.LiveProfileID = "attacker" }},
		{"channel", func(x *repository.GuardBoundSession0507) { x.LiveChannel = "attacker" }},
		{"username", func(x *repository.GuardBoundSession0507) { x.LiveUsername = "attacker" }},
		{"uuid", func(x *repository.GuardBoundSession0507) { x.LiveUUID = "attacker" }},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := b
			tc.tamper(&corrupted)
			if guardBoundLiveMatches0507(corrupted) {
				t.Fatal("Ошибочно принят изменённый активный сеанс игрока")
			}
		})
	}
}
