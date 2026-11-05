package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

const validationSchema0345 = "launcher.validation-evidence.v4"
const validationDomain0345 = "Launcher/validation-evidence/v4\x00"

// Порядок полей является частью подписанной канонической сериализации JSON. Все
// скалярные метаданные должны быть ASCII без метасимволов HTML; карты JSON сортируют
// ключи в Go и канонической реализации аттестатора.
type validationPayload0345 struct {
	SchemaVersion        string            `json:"schemaVersion"`
	RunNonce             string            `json:"runNonce"`
	Audience             string            `json:"audience"`
	Purpose              string            `json:"purpose"`
	TargetID             string            `json:"targetId"`
	TargetMatrixSHA256   string            `json:"targetMatrixSha256"`
	SignerKeyID          string            `json:"signerKeyId"`
	PackageVersion       string            `json:"packageVersion"`
	RunID                string            `json:"runId"`
	PackageID            string            `json:"packageId"`
	ManifestSHA256       string            `json:"manifestSha256"`
	ArtifactSHA256       string            `json:"artifactSha256"`
	ResolvedPlanSHA256   string            `json:"resolvedPlanSha256"`
	SourceSHA            string            `json:"sourceSha"`
	BuildSHA             string            `json:"buildSha"`
	RunnerImageSHA256    string            `json:"runnerImageSha256"`
	JavaSHA256           string            `json:"javaSha256"`
	JavaVersion          string            `json:"javaVersion"`
	OS                   string            `json:"os"`
	Arch                 string            `json:"arch"`
	Loader               string            `json:"loader"`
	InstallAdapterSHA256 string            `json:"installAdapterSha256"`
	GuardMode            string            `json:"guardMode"`
	GuardPolicySHA256    string            `json:"guardPolicySha256"`
	ServerBridgeSHA256   string            `json:"serverBridgeSha256"`
	ServerPluginVersion  string            `json:"serverPluginVersion"`
	Preset               string            `json:"preset"`
	AuthenticationMode   string            `json:"authenticationMode"`
	Stages               map[string]string `json:"stages"`
	ArtifactHashes       map[string]string `json:"artifactHashes"`
	StartedAt            string            `json:"startedAt"`
	FinishedAt           string            `json:"finishedAt"`
	IssuedAt             string            `json:"issuedAt"`
	ExpiresAt            string            `json:"expiresAt"`
}
type signedValidation0345 struct {
	Evidence  validationPayload0345 `json:"evidence"`
	Signature string                `json:"signature"`
}
type validationAttestationRepository0345 interface {
	ListStagedRuns0342(context.Context, string) ([]model.StagedRuntimeRun0342, error)
	SaveValidationAttestation0345(context.Context, model.ValidationAttestation0345) error
	ListValidationAttestations0345(context.Context, string) ([]model.ValidationAttestation0345, error)
}

var validationHex0345 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var validationToken0345 = regexp.MustCompile(`^[a-zA-Z0-9_.:/@+\-]{1,160}$`)
var mandatoryStages0345 = []string{"manifest-files", "materialization", "startup", "loader-readiness", "authentication", "server-readiness", "matching-server", "gameplay-smoke", "update-recovery"}
var stageArtifacts0345 = map[string]string{"materialization": "verified.json", "startup": "startup-readiness.json", "loader-readiness": "startup-readiness.json", "authentication": "authentication.json", "server-readiness": "server-readiness.json", "matching-server": "gameplay-smoke.json", "gameplay-smoke": "gameplay-smoke.json", "update-recovery": "update-recovery.json"}

func validatePayload0345(p validationPayload0345) error {
	if !validationPreset0348.MatchString(p.Preset) {
		return errors.New("Некорректный выбор подписанного пресета")
	}
	if p.SchemaVersion != validationSchema0345 {
		return errors.New("Некорректная схема подтверждения")
	}
	for _, v := range []string{p.ManifestSHA256, p.ArtifactSHA256, p.ResolvedPlanSHA256, p.BuildSHA, p.RunnerImageSHA256, p.JavaSHA256, p.InstallAdapterSHA256, p.GuardPolicySHA256, p.ServerBridgeSHA256, p.RunNonce, p.TargetMatrixSHA256, p.SignerKeyID} {
		if !validationHex0345.MatchString(v) {
			return errors.New("Некорректный подписанный хеш")
		}
	}
	if !(validationHex0345.MatchString(p.SourceSHA) || (len(p.SourceSHA) == 40 && regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.SourceSHA))) {
		return errors.New("Некорректное значение: источник SHA")
	}
	for _, v := range []string{p.RunID, p.PackageID, p.JavaVersion, p.OS, p.Arch, p.Loader, p.GuardMode, p.ServerPluginVersion, p.Audience, p.Purpose, p.TargetID, p.PackageVersion, p.AuthenticationMode} {
		if !validationToken0345.MatchString(v) {
			return errors.New("Недействительная подписанная идентификация запуска")
		}
	}
	if p.AuthenticationMode != "official" && p.AuthenticationMode != "custom" {
		return errors.New("Неподдерживаемая целевая платформа реальной авторизации")
	}
	if len(p.Stages) != len(mandatoryStages0345) {
		return errors.New("Матрица этапов Runtime заполнена не полностью")
	}
	for _, stage := range mandatoryStages0345 {
		if p.Stages[stage] != "passed" {
			return fmt.Errorf("Обязательный этап Runtime %s не пройден", stage)
		}
	}
	if len(p.ArtifactHashes) < 6 || len(p.ArtifactHashes) > 24 {
		return errors.New("Отсутствуют или избыточны независимо проверенные хеши артефактов")
	}
	for k, v := range p.ArtifactHashes {
		if !validationToken0345.MatchString(k) || !validationHex0345.MatchString(v) {
			return errors.New("Некорректное значение: хеш артефакта")
		}
	}
	for _, name := range []string{"staged-execution.json", "verified.json", "startup-readiness.json", "server-readiness.json", "gameplay-smoke.json", "authentication.json", "runtime-launch.json", "runtime-gameplay-launch.json", "execution-identity.json", "update-recovery.json"} {
		if !validationHex0345.MatchString(p.ArtifactHashes[name]) {
			return fmt.Errorf("Отсутствует обязательный артефакт: %s", name)
		}
	}
	// Начиная с 0.43.14 приёмка игрового процесса должна связывать исходные байты
	// ОТДЕЛЬНОГО adversarial-запуска с этим независимо подписанным наблюдением.
	// Прежний PASS девяти этапов нельзя повторно использовать как новый игровой
	// сертификат.
	var major, minor, patch int
	if count, _ := fmt.Sscanf(p.PackageVersion, "%d.%d.%d", &major, &minor, &patch); count == 3 &&
		(major > 0 || minor > 43 || (minor == 43 && patch >= 14)) {
		if !validationHex0345.MatchString(p.ArtifactHashes["adversarial-gameplay-04314.json"]) {
			return errors.New("Отсутствует независимо проверенный игровой артефакт adversarial-тестирования")
		}
	}
	start, e := time.Parse(time.RFC3339Nano, p.StartedAt)
	if e != nil {
		return errors.New("Некорректное время начала")
	}
	end, e := time.Parse(time.RFC3339Nano, p.FinishedAt)
	if e != nil || end.Before(start) || end.Sub(start) > 4*time.Hour || end.After(time.Now().Add(5*time.Minute)) {
		return errors.New("Некорректный временной интервал аттестации")
	}
	return nil
}
func verifyValidation0345(p signedValidation0345, publicKey string) error {
	rawKey, e := base64.RawURLEncoding.DecodeString(publicKey)
	if e != nil || len(rawKey) != ed25519.PublicKeySize {
		return errors.New("Доверенный ключ подписания подтверждений не настроен")
	}
	if e = validatePayload0345(p.Evidence); e != nil {
		return e
	}
	fingerprint, e := validationKeyFingerprint0346(publicKey)
	if e != nil || fingerprint != p.Evidence.SignerKeyID {
		return errors.New("Отпечаток ключа аттестации не совпадает")
	}
	signature, e := base64.RawURLEncoding.DecodeString(p.Signature)
	if e != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("Некорректный формат подписи аттестации")
	}
	canonical, e := json.Marshal(p.Evidence)
	if e != nil {
		return e
	}
	message := append([]byte(validationDomain0345), canonical...)
	if !ed25519.Verify(ed25519.PublicKey(rawKey), message, signature) {
		return errors.New("Недоверенный подписант аттестации или изменённые свидетельства")
	}
	return nil
}
func matchObservation0345(p validationPayload0345, run model.StagedRuntimeRun0342) error {
	if run.RunID != p.RunID || run.PackageID != p.PackageID || run.ManifestSHA256 != p.ManifestSHA256 || run.ArtifactSHA256 != p.ArtifactSHA256 {
		return errors.New("Результат запуска не совпадает с сохранённым неизменяемым снимком staging-окружения")
	}
	begin, e := time.Parse(time.RFC3339Nano, p.StartedAt)
	if e != nil || !begin.Equal(run.StartedAt) {
		return errors.New("Время начала в подтверждении отличается от отчёта о выполнении")
	}
	finish, e := time.Parse(time.RFC3339Nano, p.FinishedAt)
	if e != nil || !finish.Equal(run.FinishedAt) {
		return errors.New("Время окончания в подтверждении отличается от отчёта о выполнении")
	}
	var stages map[string]stagedStep0342
	if e = json.Unmarshal(run.Stages, &stages); e != nil {
		return e
	}
	for _, stage := range mandatoryStages0345 {
		record, ok := stages[stage]
		if !ok || record.Status != p.Stages[stage] || record.Status != "passed" {
			return errors.New("Подписанный этап противоречит сохранённому отчёту о выполнении: " + stage)
		}
		if name, ok := stageArtifacts0345[stage]; ok && record.EvidenceSHA256 != p.ArtifactHashes[name] {
			return errors.New("Подписанный артефакт свидетельств не совпадает с сохранённым этапом:" + stage)
		}
	}
	return nil
}
func (s Server) validationAttestationPost0345(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(validationAttestationRepository0345)
	if !ok {
		writeError(w, 503, "Хранилище подтверждений проверки недоступно")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	incoming, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		writeError(w, 400, "Некорректные или слишком большие данные проверки")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(incoming))
	dec.DisallowUnknownFields()
	var signed signedValidation0345
	var extra any
	decodeErr := dec.Decode(&signed)
	if decodeErr == nil {
		if e := dec.Decode(&extra); e != io.EOF {
			decodeErr = errors.New("Обнаружены лишние данные после: свидетельство")
		}
	}
	if decodeErr != nil {
		if e := s.saveValidationDecision03412(r.Context(), r.PathValue("packageId"), "", "attestation", "rejected",
			"malformed-evidence", digestValidationAttempt03412(incoming)); e != nil {
			writeError(w, 503, "Журнал проверок недоступен")
			return
		}
		writeError(w, 400, "Неверный формат доказательств проверки")
		return
	}
	deny := func(err error) {
		// Сохраняйте отказ в виде хеша и ограниченного кода причины, а не переданного
		// оператором JSON, ID учётных записей или сырых диагностических данных.
		auditErr := s.saveValidationDecision03412(r.Context(), r.PathValue("packageId"), signed.Evidence.RunID,
			"attestation", "rejected", validationDecisionReason03412(err), safeValidationDecisionDigest03412(signed))
		if auditErr != nil {
			writeError(w, 503, "Журнал проверок недоступен")
			return
		}
		s.Repo.AddAuditEvent(model.AuditEvent{Actor: s.adminActor(r), Action: "validation-attestation:rejected", Target: r.PathValue("packageId"), JobID: signed.Evidence.RunID, ReasonCode: "attestation-invalid-0345", CreatedAt: time.Now().UTC()})
		writeError(w, 409, err.Error())
	}
	if e := verifyValidation0345(signed, s.Config.ValidationAttestationPublicKey0345); e != nil {
		deny(e)
		return
	}
	p := signed.Evidence
	fingerprint, e := validationKeyFingerprint0346(s.Config.ValidationAttestationPublicKey0345)
	if e != nil || fingerprint != p.SignerKeyID {
		deny(errors.New("Недоверенный идентификатор ключа подписи"))
		return
	}
	freshStore, ok := s.Repo.(validationFreshnessStore0346)
	if !ok {
		writeError(w, 503, "Хранилище актуальности проверок недоступно")
		return
	}
	if e = validateFreshness0346(r.Context(), freshStore, p, time.Now().UTC(), true); e != nil {
		deny(e)
		return
	}
	if !validationHex0345.MatchString(s.Config.ValidationTrustedRunnerImageSHA2560345) || p.RunnerImageSHA256 != s.Config.ValidationTrustedRunnerImageSHA2560345 {
		deny(errors.New("Недоверенный или не настроенный закреплённый образ runner"))
		return
	}
	if p.PackageID != r.PathValue("packageId") {
		deny(errors.New("Несовпадение: пакет аттестации"))
		return
	}
	lookup, e := s.lookupPackage(p.PackageID)
	if e != nil {
		deny(errors.New("Отсутствует: пакет аттестации"))
		return
	}
	if lookup.Release.Version != p.PackageVersion {
		deny(errors.New("Версия выпуска в аттестации не совпадает"))
		return
	}
	targets, matrixSHA, policyErr := configuredTargets0346(s.Config.ValidationRequiredTargetsJSON0346, lookup.Release, p.ManifestSHA256, p.ArtifactSHA256)
	if policyErr != nil || matrixSHA != p.TargetMatrixSHA256 {
		deny(errors.New("Подтверждение больше не соответствует обязательной целевой политике"))
		return
	}
	targetMatched := false
	for _, target := range targets {
		if matchingTarget0346(p, target) {
			targetMatched = true
			break
		}
	}
	if !targetMatched {
		deny(errors.New("Параметры Java, пресета, загрузчика, сервера, адаптера или целевой сборки в аттестации не совпадают"))
		return
	}
	if lookup.Release.Status != "integrity-passed" {
		deny(errors.New("Подготовленный пакет не прошёл проверку целостности"))
		return
	}
	// Ключ проверки НИКОГДА не должен быть ключом подписи релиза или манифеста
	// проекта. Даже корректно подписанный отчёт CI не может наследовать доверие к
	// релизу.
	if lookup.Release.Manifest.Signature != nil {
		attestorKey, errAttestor := base64.RawURLEncoding.DecodeString(s.Config.ValidationAttestationPublicKey0345)
		manifestKey, errManifest := hex.DecodeString(lookup.Release.Manifest.Signature.PublicKey)
		if errAttestor == nil && errManifest == nil && bytes.Equal(attestorKey, manifestKey) {
			deny(errors.New("Ключ подписанта аттестации должен отличаться от ключа подписи выпуска"))
			return
		}
	}
	md, e := manifestDigest0212(lookup.Release.Manifest)
	if e != nil || md != p.ManifestSHA256 {
		deny(errors.New("Манифест изменён после выполнения"))
		return
	}
	fd, e := artifactDigest0212(lookup.Files)
	if e != nil || fd != p.ArtifactSHA256 {
		deny(errors.New("Подготовленные файлы изменены после выполнения"))
		return
	}
	if e = s.verifyManifestSignature(lookup.Release.Manifest); e != nil {
		deny(errors.New("Некорректное значение: подпись манифеста"))
		return
	}
	if !manifestFilesMatch0212(lookup.Release.Manifest, lookup.Files) {
		deny(errors.New("Несоответствие: manifest/file"))
		return
	}
	check, e := s.Repo.LatestIntegrityCheck(r.Context(), p.PackageID)
	if e != nil || check.Result != "passed" || check.ManifestDigest != md || check.ArtifactDigest != fd {
		deny(errors.New("Отсутствует актуальное доказательство целостности"))
		return
	}
	runs, e := store.ListStagedRuns0342(r.Context(), p.PackageID)
	if e != nil {
		writeError(w, 503, "Не удалось прочитать подготовленные запуски Runtime")
		return
	}
	matched := false
	for _, run := range runs {
		if run.RunID == p.RunID {
			if e = matchObservation0345(p, run); e != nil {
				deny(e)
				return
			}
			matched = true
			break
		}
	}
	if !matched {
		deny(errors.New("Не найден сохранённый запуск для аттестации"))
		return
	}
	// Повторно проверьте текущую целевую политику и отзыв ключа после дорогих проверок
	// запуска и хранилища — непосредственно до вставки неизменяемого свидетельства.
	// Это не разрешает продвижение stable: триггер stable БД остаётся активным.
	if e = validateFreshness0346(r.Context(), freshStore, p, time.Now().UTC(), true); e != nil {
		deny(e)
		return
	}
	finalTargets, finalMatrix, finalErr := configuredTargets0346(s.Config.ValidationRequiredTargetsJSON0346, lookup.Release, md, fd)
	if finalErr != nil || finalMatrix != p.TargetMatrixSHA256 || len(finalTargets) != len(targets) {
		deny(errors.New("Целевая политика изменилась во время подтверждения"))
		return
	}
	raw, _ := json.Marshal(p)
	record := model.ValidationAttestation0345{RunID: p.RunID, PackageID: p.PackageID, ProjectID: lookup.Release.ProjectID, ManifestSHA256: md, ArtifactSHA256: fd, Evidence: raw, Signature: signed.Signature, ReceivedAt: time.Now().UTC()}
	if e = store.SaveValidationAttestation0345(r.Context(), record); e != nil {
		deny(errors.New("Подтверждение уже записано или возник конфликт хранилища"))
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: s.adminActor(r), Action: "validation-attestation:recorded", Target: p.PackageID, JobID: p.RunID, ReasonCode: "trusted-runner-evidence-0345-not-stable-eligible", CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "no-store")
	coverage := s.evaluateStableRelease03411(r.Context(), lookup)
	writeJSON(w, 201, map[string]any{"data": map[string]any{"runId": p.RunID, "attestationVerified": true, "stablePublishEligible": coverage.Eligible, "targetCoverage": coverage.TargetCoverage, "targetBlockers": coverage.TargetBlockers}})
}
func (s Server) validationAttestationList0345(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(validationAttestationRepository0345)
	if !ok {
		writeError(w, 503, "Хранилище подтверждений недоступно")
		return
	}
	rows, e := store.ListValidationAttestations0345(r.Context(), r.PathValue("packageId"))
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	coverage := map[string]bool{}
	reasons := map[string]string{}
	release, e := s.lookupPackage(r.PathValue("packageId"))
	if e == nil {
		md, em := manifestDigest0212(release.Release.Manifest)
		fd, ef := artifactDigest0212(release.Files)
		if em == nil && ef == nil {
			targets, matrix, policyErr := configuredTargets0346(s.Config.ValidationRequiredTargetsJSON0346, release.Release, md, fd)
			if policyErr == nil {
				for _, target := range targets {
					coverage[target.ID] = false
					reasons[target.ID] = "Отсутствует актуальная подходящая подписанная аттестация"
				}
				freshStore, ok := s.Repo.(validationFreshnessStore0346)
				for _, v := range rows {
					var p validationPayload0345
					if !ok || json.Unmarshal(v.Evidence, &p) != nil || p.TargetMatrixSHA256 != matrix || v.ManifestSHA256 != md || v.ArtifactSHA256 != fd {
						continue
					}
					signed := signedValidation0345{Evidence: p, Signature: v.Signature}
					if verifyValidation0345(signed, s.Config.ValidationAttestationPublicKey0345) != nil || validateFreshness0346(r.Context(), freshStore, p, time.Now().UTC(), false) != nil {
						continue
					}
					for _, target := range targets {
						if matchingTarget0346(p, target) {
							coverage[target.ID] = true
							delete(reasons, target.ID)
						}
					}
				}
			} else {
				reasons["policy"] = policyErr.Error()
			}
		}
	}
	if e == nil && repository.IsStableChannel0341(release.Release.Channel) {
		effective := s.evaluateStableRelease03411(r.Context(), release)
		coverage = effective.TargetCoverage
		reasons = effective.TargetBlockers
	}
	allPassed := len(coverage) > 0
	for _, passed := range coverage {
		if !passed {
			allPassed = false
		}
	}
	var requiredSelections []string
	uncheckedCombinations := 0
	if e == nil {
		requiredSelections, uncheckedCombinations, _ = RequiredMatrixSelections0348(release.Release.Manifest.ComponentCatalog)
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"attestations": rows,
		"targetCoverage": coverage, "targetBlockers": reasons,
		"requiredComponentSelections":     requiredSelections,
		"unverifiedCandidateCombinations": uncheckedCombinations,
		"allRequiredTargetsVerified":      allPassed, "stablePublishEligible": allPassed && e == nil && repository.IsStableChannel0341(release.Release.Channel)}})
}
