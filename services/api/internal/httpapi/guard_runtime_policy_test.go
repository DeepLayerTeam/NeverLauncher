package httpapi

import (
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestRuntimePolicy0317NormalizationAndValidation(t *testing.T) {
	hash := strings.Repeat("a", 64)
	profiles, err := normalizeGuardRuntimeProfiles0317([]guardRuntimeProfile0317{{JavaMajor: 21, ModuleSetSHA256: strings.ToUpper(hash)}})
	if err != nil || len(profiles) != 1 || profiles[0].ModuleSetSHA256 != hash {
		t.Fatalf("Нормализация: %#v %v", profiles, err)
	}
	if got := guardRuntimePolicyDigest0317(profiles); !isSHA256Hex0134(got) {
		t.Fatalf("Недопустимый хеш политики Runtime %q", got)
	}
	policy := guardReleasePolicy0134{RuntimeProfiles: map[string][]guardRuntimeProfile0317{"windows": profiles}}
	valid := guardContinuousEvidence01810{JavaMajor: 21, ModuleSetSHA256: hash}
	before, err := verifyGuardRuntimePolicy0317(policy, "windows", valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*guardContinuousEvidence01810){
		"java-major": func(e *guardContinuousEvidence01810) { e.JavaMajor = 17 },
		"modules":    func(e *guardContinuousEvidence01810) { e.ModuleSetSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			e := valid
			mutate(&e)
			if _, err := verifyGuardRuntimePolicy0317(policy, "windows", e); err == nil {
				t.Fatal("Принят неодобренный Runtime")
			}
		})
	}
	policy.RuntimeProfiles["windows"] = []guardRuntimeProfile0317{{JavaMajor: 21, ModuleSetSHA256: strings.Repeat("b", 64)}}
	after := guardRuntimePolicyDigest0317(policy.RuntimeProfiles["windows"])
	if before == after {
		t.Fatal("Замена политики сохранила прежний дайджест")
	}
	malformed := [][]guardRuntimeProfile0317{
		{{JavaMajor: 22, ModuleSetSHA256: hash}},
		{{JavaMajor: 21, ModuleSetSHA256: "abc"}},
		{{JavaMajor: 21, ModuleSetSHA256: hash, CodeSetSHA256: "abc"}},
		{{JavaMajor: 21, ModuleSetSHA256: hash, HookSetSHA256: "abc"}},
		{{JavaMajor: 21, ModuleSetSHA256: hash}, {JavaMajor: 21, ModuleSetSHA256: hash}},
	}
	for n, bad := range malformed {
		if _, err := normalizeGuardRuntimeProfiles0317(bad); err == nil {
			t.Fatalf("Принят недопустимый профиль Runtime %d", n)
		}
	}
	if !guardRuntimePolicyRequired0317("0.31.7") || !guardRuntimePolicyRequired0317("0.32.0") || guardRuntimePolicyRequired0317("0.31.6") {
		t.Fatal("Некорректная проверка версии политики")
	}
}

func TestRuntimePolicy0317RejectsMissingOrMalformedAllowlist(t *testing.T) {
	cfg := config.Config{Environment: "test", GuardReleaseAllowlistJSON: `{"schemaVersion":"2.0","releases":{"0.31.7":{"protocolVersion":4,"platforms":{"windows":{"signingMode":"authenticode","artifacts":[{"guardSha256":"` + strings.Repeat("a", 64) + `","launcherSha256":"` + strings.Repeat("b", 64) + `","requireAuthenticode":true}]}}}}}`}
	server := Server{Version: "0.31.7", Config: cfg}
	if _, err := server.guardReleasePolicies0134(); err == nil {
		t.Fatal("В релизе 0.31.7 незаметно допущено отсутствие runtimeProfiles")
	}
	cfg.GuardReleaseAllowlistJSON = strings.Replace(cfg.GuardReleaseAllowlistJSON, `}]}}}}}`, `}],"runtimeProfiles":[{"javaMajor":21,"moduleSetSha256":"`+strings.Repeat("c", 64)+`"}]}}}}}`, 1)
	server.Config = cfg
	policies, err := server.guardReleasePolicies0134()
	if err != nil {
		t.Fatalf("Корректный профиль Runtime ошибочно отклонён: %v", err)
	}
	if len(policies["0.31.7"].RuntimeProfiles["windows"]) != 1 {
		t.Fatal("Профиль Runtime не сохранился после нормализации релиза")
	}
}

func TestGuardProcessID0317RejectsControlCharacters(t *testing.T) {
	for _, good := range []string{"runtime-1700000000-1234", "abc:123", "A_B.c"} {
		if !validGuardProcessID0317(good) {
			t.Fatalf("Корректный идентификатор процесса ошибочно отклонён: %q", good)
		}
	}
	for _, bad := range []string{"", " with-space", "one\\ntwo", "foo/bar", strings.Repeat("a", 129)} {
		if validGuardProcessID0317(bad) {
			t.Fatalf("Принят некорректный идентификатор процесса: %q", bad)
		}
	}
	e := guardContinuousEvidence01810{Schema: guardContinuousEvidenceSchema01810, EvidenceVersion: 2, ProcessID: "runtime:123", RuntimePID: 10}
	// Некорректный идентификатор должен отклоняться до любых других проверок
	// состояния Runtime.
	e.ProcessID = "one\ntwo"
	if err := validateGuardContinuousEvidence01810(e, time.Now()); err == nil {
		t.Fatal("Принят неверно сформированный идентификатор процесса")
	}
}

func TestGuardRuntime0317MinecraftSessionBinding(t *testing.T) {
	h := func(ch string) string { return strings.Repeat(ch, 64) }
	ticket := model.DeviceChallenge{ID: "one-use-runtime", Metadata: map[string]any{
		"minecraftSessionId": "minecraft-A", "launcherVersion": "0.31.7",
		"guardSha256": h("a"), "launcherSha256": h("b"),
	}}
	session := model.MinecraftSession{ID: "minecraft-A", IntegrityVerified: true, LauncherVersion: "0.31.7", GuardSHA256: h("a"), LauncherSHA256: h("b")}
	if err := validateContinuousGuardTicketForMinecraftSession01810(ticket, session); err != nil {
		t.Fatalf("Отклонён привязанный релиз: %v", err)
	}
	session.ID = "minecraft-B"
	if err := validateContinuousGuardTicketForMinecraftSession01810(ticket, session); err == nil {
		t.Fatal("Подтверждение Runtime разрешило постороннюю сессию Minecraft")
	}
	session.ID = "minecraft-A"
	delete(ticket.Metadata, "minecraftSessionId")
	if err := validateContinuousGuardTicketForMinecraftSession01810(ticket, session); err == nil {
		t.Fatal("Принят непривязанный билет Runtime версии 0.31.7")
	}
	ticket.Metadata["minecraftSessionId"] = "minecraft-A"
	session.CreatedAt = time.Now().UTC()
	ticket.CreatedAt = session.CreatedAt.Add(-time.Minute)
	if err := validateContinuousGuardTicketForMinecraftSession01810(ticket, session); err == nil {
		t.Fatal("Билет Runtime создан до запуска сессии")
	}
}

func TestRuntimePolicy0317AdditionalHashPinning(t *testing.T) {
	h := func(ch string) string { return strings.Repeat(ch, 64) }
	profiles, err := normalizeGuardRuntimeProfiles0317([]guardRuntimeProfile0317{{JavaMajor: 21, ModuleSetSHA256: h("a"), CodeSetSHA256: h("b"), HookSetSHA256: h("c")}})
	if err != nil {
		t.Fatal(err)
	}
	if !guardRuntimeMatches0317(profiles, 21, h("a"), h("b"), h("c")) {
		t.Fatal("Отклонены точно закреплённые код и перехватчики")
	}
	if guardRuntimeMatches0317(profiles, 21, h("a"), h("d"), h("c")) {
		t.Fatal("Принята подмена кода")
	}
	if guardRuntimeMatches0317(profiles, 21, h("a"), h("b"), h("d")) {
		t.Fatal("Принята подмена перехватчика")
	}
}

func TestGuardVersionGateFailsClosedOnNonCanonicalVersion0496(t *testing.T) {
	for _, invalid := range []string{"0.31.7evil", "0.31.7/other", " 0.31.7", "00.31.7", "0.31.07", "0.31.7\n0.30.0", "999999999999.31.7"} {
		if !guardRuntimePolicyRequired0317(invalid) {
			t.Fatalf("Неверно сформированный релиз обошёл Guard: %q", invalid)
		}
	}
	for _, valid := range []string{"0.31.7", "0.49.6", "0.49.6-rc.1", "0.49.6+build.1"} {
		if !guardRuntimePolicyRequired0317(valid) {
			t.Fatalf("Корректный релиз не прошёл проверку: %q", valid)
		}
	}
}
