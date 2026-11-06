package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestV07FailClosedRealProviderAttestation(t *testing.T) {
	signed, private, public := validValidationFixture0345(t)
	if signed.Evidence.AuthenticationMode != "official" {
		t.Fatal("Тестовый сценарий требует настоящего официального режима авторизации")
	}
	if err := verifyValidation0345(signed, public); err != nil {
		t.Fatal(err)
	}
	// Даже корректно подписанный результат mock, skipped, inconclusive или
	// отсутствие результата провайдера не сертифицирует подготовленный Runtime.
	for _, status := range []string{"mock", "inconclusive", "blocked", "failed", "skipped", ""} {
		t.Run("stage-"+status, func(t *testing.T) {
			changed := signed
			changed.Evidence.Stages = make(map[string]string, len(signed.Evidence.Stages))
			for k, v := range signed.Evidence.Stages {
				changed.Evidence.Stages[k] = v
			}
			changed.Evidence.Stages["authentication"] = status
			signFixture0345(t, &changed, private)
			if err := verifyValidation0345(changed, public); err == nil {
				t.Fatal("Сертифицирована синтетическая или неподтверждённая авторизация")
			}
		})
	}
	for _, mode := range []string{"", "mock", "offline", "none"} {
		changed := signed
		changed.Evidence.AuthenticationMode = mode
		signFixture0345(t, &changed, private)
		if err := verifyValidation0345(changed, public); err == nil {
			t.Fatalf("Принят запрещённый режим авторизации %q", mode)
		}
	}
	other := signed
	other.Evidence.AuthenticationMode = "custom"
	signFixture0345(t, &other, private)
	if err := verifyValidation0345(other, public); err != nil {
		t.Fatal(err)
	}
	if matchingTarget0346(other.Evidence, testTarget0346(signed.Evidence)) {
		t.Fatal("Действительная подпись другого провайдера ошибочно получила статус официального провайдера")
	}
}

func TestV07MissingAuthTargetAndAuthStageRejected(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	release := model.ReleaseVersion{ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: signed.Evidence.PackageVersion}
	target := testTarget0346(signed.Evidence)
	target.AuthenticationMode = ""
	blob, _ := json.Marshal([]validationTarget0346{target})
	if _, _, err := configuredTargets0346(string(blob), release, signed.Evidence.ManifestSHA256, signed.Evidence.ArtifactSHA256); err == nil {
		t.Fatal("Принята цель без режима провайдера")
	}
	now := time.Now().UTC()
	grant := stagedGrant0342{Schema: stagedGrantSchema0342, PackageID: signed.Evidence.PackageID,
		RunID: signed.Evidence.RunID, ManifestSHA256: signed.Evidence.ManifestSHA256,
		ArtifactSHA256: signed.Evidence.ArtifactSHA256, ExpiresAt: now.Add(time.Hour).Unix()}
	report := stagedRunReport0342{Schema: stagedRunSchema0342, PackageID: grant.PackageID,
		RunID: grant.RunID, ManifestSHA256: grant.ManifestSHA256, ArtifactSHA256: grant.ArtifactSHA256,
		StartedAt: now.Add(-time.Minute), FinishedAt: now,
		Stages: map[string]stagedStep0342{"authentication": {Status: "inconclusive", Detail: "provider outage"}}}
	if err := validateStagedRunReport0342(grant, report); err != nil {
		t.Fatalf("Отклонена диагностика недоступности провайдера: %v", err)
	}
	report.Stages["authentication"] = stagedStep0342{Status: "passed", EvidenceSHA256: strings.Repeat("a", 64)}
	if err := validateStagedRunReport0342(grant, report); err != nil {
		t.Fatalf("Отклонена диагностика дайджеста этапа авторизации: %v", err)
	}
	// Недоверенный staging-отчёт никогда непосредственно не сертифицирует релиз;
	// в доверенное хранилище могут попадать только свидетельства v4 отдельно
	// закреплённого аттестатора.
}
