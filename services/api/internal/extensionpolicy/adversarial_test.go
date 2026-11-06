package extensionpolicy

import (
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Дайджест означает согласие с точными ID расширения, версией, набором прав и
// политикой песочницы. Автообновления никогда не переносят согласие через
// повышение привилегий.
func TestAdversarialSignedPolicyEscalation03114(t *testing.T) {
	base := signedPolicy0318()
	base.Version = "1.0.0"
	// Одобренный выпуск изменяет привилегию и требует явного согласия.
	base.Sandbox = nil
	target := signedPolicy0318()
	target.Sandbox.MaxOutputBytes = 1 << 20
	approved, err := ApprovalDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReview(base, target, approved); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*model.ExtensionManifest){
		"foreign-extension": func(m *model.ExtensionManifest) { m.ID = "evil.publisher" },
		"next-version":      func(m *model.ExtensionManifest) { m.Version = "99.0.0" },
		"new-permission":    func(m *model.ExtensionManifest) { m.Permissions = append(m.Permissions, "secrets:read") },
		"new-secret":        func(m *model.ExtensionManifest) { m.Sandbox.Secrets = append(m.Sandbox.Secrets, "second_token") },
		"new-outbound": func(m *model.ExtensionManifest) {
			m.Sandbox.NetworkOutbound = append(m.Sandbox.NetworkOutbound, "outside.example.com:443")
		},
		"new-shared-root": func(m *model.ExtensionManifest) {
			m.Sandbox.FilesystemRead = append(m.Sandbox.FilesystemRead, "shared:backend")
		},
		"weakened-mode":    func(m *model.ExtensionManifest) { m.Sandbox.Mode = "trusted" },
		"increased-pids":   func(m *model.ExtensionManifest) { m.Sandbox.MaxProcesses++ },
		"increased-memory": func(m *model.ExtensionManifest) { m.Sandbox.MaxMemoryBytes += 1 << 20 },
		"unlimited-output": func(m *model.ExtensionManifest) { m.Sandbox.MaxOutputBytes = 0 },
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := target
			policy := *target.Sandbox
			policy.FilesystemRead = append([]string(nil), policy.FilesystemRead...)
			policy.FilesystemWrite = append([]string(nil), policy.FilesystemWrite...)
			policy.NetworkOutbound = append([]string(nil), policy.NetworkOutbound...)
			policy.Secrets = append([]string(nil), policy.Secrets...)
			candidate.Sandbox = &policy
			attack(&candidate)
			digest, err := ApprovalDigest(candidate)
			if err == nil && digest == approved {
				t.Fatal("принят дайджест подтверждения другого расширения")
			}
			if err := RequireReview(base, candidate, approved); err == nil {
				t.Fatal("старое подтверждение разрешило изменённую политику")
			}
			if err := RequireReview(base, candidate, ""); err == nil {
				t.Fatal("допущено скрытое автоматическое повышение привилегий")
			}
		})
	}
}

// Обновление без изменения политики не может подменить подписанную идентичность
// расширения.
func TestAdversarialCrossExtensionApprovalWithoutPolicyDelta03114(t *testing.T) {
	before := signedPolicy0318()
	after := signedPolicy0318()
	after.ID = "attacker.different"
	after.Version = "1.2.0"
	if changed, err := ChangesRequireApproval(before, after); !changed || err == nil {
		t.Fatal("проверка изменения не запретила переход между расширениями")
	}
	if err := RequireReview(before, after, ""); err == nil {
		t.Fatal("чужой идентификатор расширения принят как обновление без изменения политики")
	}
	candidate, err := ApprovalDigest(after)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReview(before, after, candidate); err == nil {
		t.Fatal("даже совпадающий подписанный дайджест не должен переноситься между расширениями")
	}
}
