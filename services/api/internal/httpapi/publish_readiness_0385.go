package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// A publish refusal is a set of observed, actionable problems, not a manually
// assigned certification status. The final publish transaction still rechecks
// every trust gate and the exact bytes: this preview never issues a permit.
type publishBlocker0385 struct {
	ReasonCode string `json:"reasonCode"`
	Resource   string `json:"resource"`
	Message    string `json:"message"`
	Action     string `json:"action"`
}
type publishReadiness0385 struct {
	Eligible             bool                 `json:"eligible"`
	PackageID            string               `json:"packageId"`
	Blockers             []publishBlocker0385 `json:"blockers"`
	FinalRecheckRequired bool                 `json:"finalRecheckRequired"`
}
type publishBlocked0385 struct{ Blockers []publishBlocker0385 }

func (e publishBlocked0385) Error() string {
	if len(e.Blockers) == 0 {
		return "publish blocked"
	}
	return "publish blocked: " + e.Blockers[0].Message
}

func (s Server) evaluatePublishReadiness0385(ctx context.Context, lookup packageLookup) publishReadiness0385 {
	result := publishReadiness0385{PackageID: lookup.Release.ID, Blockers: make([]publishBlocker0385, 0), FinalRecheckRequired: true}
	add := func(code, resource, message, action string) {
		result.Blockers = append(result.Blockers, publishBlocker0385{code, resource, message, action})
	}
	release := lookup.Release
	if release.Status == "published" {
		add("package-already-published", release.ID, "Этот пакет уже опубликован и неизменяем.", "Создайте новый пакет или откройте историю канала.")
	}
	checks := s.validatePackageFiles(release, lookup.Files)
	for _, check := range checks {
		if check["status"] == "ok" {
			continue
		}
		code := "file-integrity-failed"
		if c, ok := check["reasonCode"].(string); ok && c != "" {
			code = c
		}
		add(code, fmt.Sprint(check["id"]), fmt.Sprint(check["message"]), "Восстановите файл из проверенного источника, повторите Validate → Sign → Stage → Integrity check; для неизменяемого пакета создайте новую сборку.")
	}
	if err := s.verifyManifestSignature(release.Manifest); err != nil {
		add("manifest-signature-invalid", release.ID, "Подпись манифеста отсутствует или не проходит проверку: "+err.Error(), "Проверьте файл и подпишите пакет доверенным ключом через Admin.")
	}
	if !manifestFilesMatch0212(release.Manifest, lookup.Files) {
		add("signed-file-set-mismatch", release.ID, "Подписанный список файлов не совпадает с содержимым пакета.", "Создайте новый корректный пакет и подпишите его после загрузки файлов.")
	}
	if err := validateCompatibilityManifest(release.Manifest); err != nil {
		add("manifest-compatibility-invalid", release.ID, err.Error(), "Исправьте параметры Minecraft/loader/Java и создайте новую подписанную сборку.")
	}
	md, mdErr := manifestDigest0212(release.Manifest)
	fd, fdErr := artifactDigest0212(lookup.Files)
	if mdErr != nil || fdErr != nil {
		add("digest-unavailable", release.ID, "Не удалось вычислить digest манифеста или файлов.", "Проверьте данные пакета и журнал Backend.")
	} else {
		integrity, err := s.Repo.LatestIntegrityCheck(ctx, release.ID)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			add("integrity-store-unavailable", release.ID, "Не удалось получить результат проверки целостности: "+err.Error(), "Восстановите Backend/repository перед публикацией.")
		} else if err != nil || integrity.Result != "passed" || integrity.ManifestDigest != md || integrity.ArtifactDigest != fd || !integrity.SignatureVerified || !integrity.FilesVerified || !integrity.CompatibilityVerified {
			add("integrity-pass-missing", release.ID, "Нет актуального integrity PASS, привязанного к точному манифесту и файлам.", "После исправления ошибок выполните Stage и Integrity check.")
		}
	}
	if repository.IsStableChannel0341(release.Channel) {
		coverage := s.evaluateStableRelease03411(ctx, lookup)
		keys := make([]string, 0, len(coverage.TargetBlockers))
		for key := range coverage.TargetBlockers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, target := range keys {
			add("stable-runtime-target-blocked", target, coverage.TargetBlockers[target], "Запустите необходимую проверку на целевой платформе и загрузите подписанное ValidationEvidence v4 от доверенного независимого аттестатора.")
		}
		if !coverage.Eligible && len(keys) == 0 {
			add("stable-runtime-ineligible", release.ID, "Обязательная runtime-сертификация не пройдена.", "Обновите результаты проверки обязательных targets.")
		}
	} else if err := s.validatePublishEvidenceContext0213(ctx, lookup); err != nil {
		add("runtime-policy-unsatisfied", release.ID, err.Error(), "Выполните обязательные проверки политики, загрузите проверенное runtime evidence и повторите проверку.")
	}
	result.Eligible = len(result.Blockers) == 0
	return result
}

// Convert concrete filesystem checks into a machine-readable refusal without
// treating a plain HTTP 200 validate result as a successful validation.
func fileCheckBlockers0385(checks []map[string]any) []publishBlocker0385 {
	blockers := make([]publishBlocker0385, 0)
	for _, check := range checks {
		if check["status"] == "ok" {
			continue
		}
		code := "file-integrity-failed"
		if c, ok := check["reasonCode"].(string); ok && c != "" {
			code = c
		}
		blockers = append(blockers, publishBlocker0385{ReasonCode: code, Resource: fmt.Sprint(check["id"]), Message: fmt.Sprint(check["message"]), Action: "Исправьте отсутствующий или повреждённый файл, затем повторите Validate и процедуру подписи."})
	}
	return blockers
}

// Legacy synchronous publication gets the same detailed refusal as durable
// operation preview, while preserving the original message for old clients.
func (s Server) writePublishRefusal0385(w http.ResponseWriter, r *http.Request, lookup packageLookup, message string) {
	readiness := s.evaluatePublishReadiness0385(r.Context(), lookup)
	writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"code": "publish-blocked", "reasonCode": "publish-blocked", "message": message, "blockers": readiness.Blockers, "action": "Resolve the listed blockers and validate again"}})
}
