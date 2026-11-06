package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestProductionGateFailClosedWithoutTargets03411(t *testing.T) {
	repo := repository.NewMemoryRepository("https://example.test")
	release, err := repo.CreateVersion("demo-project", "vanilla", "stable", "0.34.11-missing")
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Repo: repo}
	result := s.evaluateStableRelease03411(context.Background(), packageLookup{Release: release})
	if result.Eligible || result.Required != 0 || result.TargetBlockers["release"] == "" {
		t.Fatalf("Отсутствие политики цели не помешало стабильному релизу: %+v", result)
	}
	if _, _, err := s.issueStablePermit03411(context.Background(), packageLookup{Release: release}); err == nil {
		t.Fatal("При отсутствии подтверждений выдано разрешение на стабильный релиз")
	}
}
func TestProductionGateRequiresCompleteMatrix03411(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	p := signed.Evidence
	release := model.ReleaseVersion{ID: p.PackageID, ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion}
	a := testTarget0346(p)
	b := a
	b.ID = "other-java"
	b.JavaSHA256 = strings.Repeat("a", 64)
	raw, e := json.Marshal([]validationTarget0346{a, b})
	if e != nil {
		t.Fatal(e)
	}
	targets, matrix, e := configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256)
	if e != nil || len(targets) != 2 || matrix == "" {
		t.Fatalf("В матрице отсутствует цель: %v", e)
	}
	p.TargetMatrixSHA256 = matrix
	if matchingTarget0346(p, targets[0]) == matchingTarget0346(p, targets[1]) {
		t.Fatal("Одна аттестация должна соответствовать ровно одной отдельной цели Java")
	}
	if p.TargetID == b.ID && p.JavaSHA256 == b.JavaSHA256 {
		t.Fatal("Другая цель Java неожиданно оказалась идентичной")
	}
}
func TestProductionGateUnknownEvidenceFieldsRejected03411(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	raw, e := json.Marshal(signed.Evidence)
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"manualCertified":true}`)...)
	var decoded validationPayload0345
	if err := decodeStoredEvidence03411(raw, &decoded); err == nil {
		t.Fatal("Признак ручной сертификации не должен включаться в подписанные подтверждения")
	}
}

func TestGASourceConsistency0350(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	p := signed.Evidence
	release := model.ReleaseVersion{ID: p.PackageID, ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion}
	a := testTarget0346(p)
	b := a
	b.ID = "different-source"
	b.SourceSHA = strings.Repeat("b", 40)
	raw, err := json.Marshal([]validationTarget0346{a, b})
	if err != nil {
		t.Fatal(err)
	}
	targets, _, err := configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if targets[0].SourceSHA == targets[1].SourceSHA {
		t.Fatal("Ревизии тестовых исходников совпадают")
	}
	if _, ok := stableSourceConsistency0350(targets); ok {
		t.Fatal("Приняты разные коммиты исходников")
	}
	if got, ok := stableSourceConsistency0350(targets[:1]); !ok || got != targets[0].SourceSHA {
		t.Fatal("Совпадающие источник и цель ошибочно отклонены")
	}
	if _, ok := stableSourceConsistency0350(nil); ok {
		t.Fatal("Допущена пустая матрица источников")
	}
}
