package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/releasekeypaths"
)

const (
	releaseTrustPolicyFile0158 = "RELEASE_TRUST_POLICY.json"
	releaseTrustDomain0158     = "launcher.release.v2"
	releaseSignatureSchema0158 = "2.0"
)

type releaseTrustKey0158 struct {
	ID          string `json:"id"`
	Purpose     string `json:"purpose"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	NotBefore   string `json:"notBefore"`
	RetiredAt   string `json:"retiredAt,omitempty"`
	VerifyUntil string `json:"verifyUntil,omitempty"`
	RevokedAt   string `json:"revokedAt,omitempty"`
	ReplacedBy  string `json:"replacedBy,omitempty"`
}

type releaseTrustRootSignature0158 struct {
	Algorithm       string `json:"algorithm"`
	RootFingerprint string `json:"rootFingerprint"`
	Signature       string `json:"signature"`
	SignedAt        string `json:"signedAt"`
}

type releaseTrustPolicy0158 struct {
	SchemaVersion string                         `json:"schemaVersion"`
	TrustDomain   string                         `json:"trustDomain"`
	Epoch         uint64                         `json:"epoch"`
	IssuedAt      string                         `json:"issuedAt"`
	ExpiresAt     string                         `json:"expiresAt,omitempty"`
	Keys          []releaseTrustKey0158          `json:"keys"`
	RootSignature *releaseTrustRootSignature0158 `json:"rootSignature,omitempty"`
}

type releaseSignatureEnvelopeV2 struct {
	SchemaVersion         string `json:"schemaVersion"`
	TrustDomain           string `json:"trustDomain"`
	Algorithm             string `json:"algorithm"`
	SignedFile            string `json:"signedFile"`
	SHA256                string `json:"sha256"`
	ReleaseManifestSHA256 string `json:"releaseManifestSha256"`
	ReleaseVersion        string `json:"releaseVersion"`
	TrustEpoch            uint64 `json:"trustEpoch"`
	KeyID                 string `json:"keyId"`
	KeyFingerprint        string `json:"keyFingerprint"`
	Signature             string `json:"signature"`
	SignedAt              string `json:"signedAt"`
}

type releaseTrustState0158 struct {
	SchemaVersion                string `json:"schemaVersion"`
	TrustDomain                  string `json:"trustDomain"`
	RootFingerprint              string `json:"rootFingerprint"`
	HighestTrustEpoch            uint64 `json:"highestTrustEpoch"`
	HighestRelease               string `json:"highestReleaseVersion"`
	HighestReleaseManifestSHA256 string `json:"highestReleaseManifestSha256,omitempty"`
	LastKeyFingerprint           string `json:"lastKeyFingerprint"`
	StateRevision                uint64 `json:"stateRevision,omitempty"`
	UpdatedAt                    string `json:"updatedAt"`
}

type releaseVerificationV2Context struct {
	Policy          releaseTrustPolicy0158
	Envelope        releaseSignatureEnvelopeV2
	RootFingerprint string
	StatePath       string
}

func releaseVerificationV2Required0158(ver string) bool { return versionAtLeast0158(ver) }

func safeReleaseRelativePath0158(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || filepath.IsAbs(name) {
		return "", errors.New("Путь к релизу должен быть относительным")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("Путь релиза выходит за пределы пакета")
	}
	return clean, nil
}

func versionAtLeast0158(ver string) bool {
	a, ok := parseVersionTriple0158(ver)
	if !ok {
		return false
	}
	return compareVersionTriple0158(a, [3]int{0, 15, 8}) >= 0
}

func parseVersionTriple0158(ver string) ([3]int, bool) {
	var out [3]int
	v := strings.TrimSpace(strings.TrimPrefix(ver, "v"))
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i := range parts {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func compareVersionTriple0158(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func releaseTrustPolicyPayload0158(policy releaseTrustPolicy0158) ([]byte, error) {
	policy.RootSignature = nil
	return json.Marshal(policy)
}

func releaseSignaturePayload0158(env releaseSignatureEnvelopeV2) ([]byte, error) {
	sig := env.Signature
	env.Signature = ""
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	env.Signature = sig
	return append([]byte("Launcher-Release-Verification-v2\n"), raw...), nil
}

func fingerprintEd255190158(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func loadReleaseTrustPolicy0158(path string) (releaseTrustPolicy0158, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return releaseTrustPolicy0158{}, err
	}
	var p releaseTrustPolicy0158
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("Ошибка JSON политики доверия: %w", err)
	}
	if p.SchemaVersion != releaseSignatureSchema0158 || p.TrustDomain != releaseTrustDomain0158 || p.Epoch == 0 {
		return p, errors.New("Некорректное значение: политика доверия schema/domain/epoch")
	}
	if len(p.Keys) == 0 {
		return p, errors.New("в политике доверия отсутствуют ключи выпуска")
	}
	seenID, seenFP := map[string]bool{}, map[string]bool{}
	active := 0
	for _, k := range p.Keys {
		if strings.TrimSpace(k.ID) == "" || k.Purpose != "release-signing" || !strings.EqualFold(k.Algorithm, "Ed25519") {
			return p, fmt.Errorf("Некорректное значение: запись доверенного ключа %q", k.ID)
		}
		pubRaw, err := hex.DecodeString(strings.TrimSpace(k.PublicKey))
		if err != nil || len(pubRaw) != ed25519.PublicKeySize {
			return p, fmt.Errorf("Некорректное значение: открытый ключ %s записи доверия", k.ID)
		}
		fp := fingerprintEd255190158(ed25519.PublicKey(pubRaw))
		if !strings.EqualFold(fp, k.Fingerprint) {
			return p, fmt.Errorf("Несовпадение: отпечаток доверенного ключа %s", k.ID)
		}
		if seenID[k.ID] || seenFP[strings.ToLower(fp)] {
			return p, errors.New("в политике доверия повторяется идентификатор или отпечаток ключа")
		}
		seenID[k.ID], seenFP[strings.ToLower(fp)] = true, true
		switch k.Status {
		case "active":
			active++
		case "verify-only", "revoked":
		default:
			return p, fmt.Errorf("Некорректное значение: статус доверенного ключа %s: %s", k.ID, k.Status)
		}
	}
	if active == 0 {
		return p, errors.New("в политике доверия отсутствует активный ключ выпуска")
	}
	return p, nil
}

func verifyReleaseTrustPolicy0158(policy releaseTrustPolicy0158, rootPublicKeyPath string, now time.Time, enforceCurrentValidity bool) (string, error) {
	rootPublicKeyPath = strings.TrimSpace(rootPublicKeyPath)
	if rootPublicKeyPath == "" {
		rootPublicKeyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE"))
	}
	if rootPublicKeyPath == "" {
		rootPublicKeyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if rootPublicKeyPath == "" {
		return "", errors.New("Для проверки релиза v2 требуется внешний корневой открытый ключ")
	}
	root, err := loadEd25519PublicKey(rootPublicKeyPath)
	if err != nil {
		return "", err
	}
	fp := fingerprintEd255190158(root)
	if policy.RootSignature == nil || !strings.EqualFold(policy.RootSignature.Algorithm, "Ed25519") || !strings.EqualFold(policy.RootSignature.RootFingerprint, fp) {
		return "", errors.New("корневая подпись политики доверия не соответствует внешнему корневому якорю доверия")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(policy.RootSignature.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errors.New("Некорректное значение: кодировка корневой подписи политики доверия")
	}
	payload, err := releaseTrustPolicyPayload0158(policy)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(root, payload, sig) {
		return "", errors.New("Проверка корневой подписи политики доверия завершилась ошибкой")
	}
	if t, err := time.Parse(time.RFC3339Nano, policy.IssuedAt); err != nil || t.After(now.Add(5*time.Minute)) {
		return "", errors.New("дата выдачи политики доверия некорректна или находится в будущем")
	}
	if strings.TrimSpace(policy.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339Nano, policy.ExpiresAt)
		if err != nil {
			return "", errors.New("Некорректное значение: политика доверия expiresAt")
		}
		if enforceCurrentValidity && !now.Before(t) {
			return "", errors.New("Истёк срок действия: политика доверия")
		}
	}
	return fp, nil
}

func findTrustedReleaseKey0158(policy releaseTrustPolicy0158, id, fp string, signedAt time.Time) (ed25519.PublicKey, error) {
	for _, k := range policy.Keys {
		if k.ID != id || !strings.EqualFold(k.Fingerprint, fp) {
			continue
		}
		if k.Status == "revoked" {
			return nil, fmt.Errorf("Ключ подписи релиза отозван: %s", id)
		}
		if k.Status != "active" && k.Status != "verify-only" {
			return nil, fmt.Errorf("статус ключа выпуска не допускает проверку: %s", k.Status)
		}
		if strings.TrimSpace(k.NotBefore) != "" {
			t, err := time.Parse(time.RFC3339Nano, k.NotBefore)
			if err != nil || signedAt.Before(t.Add(-5*time.Minute)) {
				return nil, fmt.Errorf("Подпись релиза создана до активации ключа: %s", id)
			}
		}
		if k.Status == "verify-only" {
			// Ключ только для проверки не может разрешать новые артефакты подменой даты SignedAt
			// задним числом. Период перекрытия истекает по реальным часам.
			retired, err := time.Parse(time.RFC3339Nano, k.RetiredAt)
			if err != nil || signedAt.After(retired.Add(5*time.Minute)) {
				return nil, fmt.Errorf("Подпись релиза создана после вывода ключа из эксплуатации: %s", id)
			}
			limit := retired.Add(48 * time.Hour)
			if k.VerifyUntil != "" {
				end, e := time.Parse(time.RFC3339Nano, k.VerifyUntil)
				if e != nil || !end.After(retired) || end.After(limit) {
					return nil, fmt.Errorf("Некорректное значение: ограниченный период одновременного действия ключей выпуска: %s", id)
				}
				limit = end
			}
			if !time.Now().UTC().Before(limit) {
				return nil, fmt.Errorf("Истёк срок действия: пересечение сроков действия ключей выпуска: %s", id)
			}
		}
		raw, _ := hex.DecodeString(k.PublicKey)
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("ключ выпуска отсутствует в доверенной политике: id=%s fingerprint=%s", id, fp)
}

func loadTrustState0158(path string) (releaseTrustState0158, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return releaseTrustState0158{SchemaVersion: releaseTrustStateSchema01510, TrustDomain: releaseTrustDomain0158}, nil
	}
	if err != nil {
		return releaseTrustState0158{}, err
	}
	var s releaseTrustState0158
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	if (s.SchemaVersion != releaseSignatureSchema0158 && s.SchemaVersion != releaseTrustStateSchema01510) || s.TrustDomain != releaseTrustDomain0158 {
		return s, errors.New("Некорректное значение: релиз состояние доверия schema/domain")
	}
	if s.HighestReleaseManifestSHA256 != "" && !validSHA256Hex0157(s.HighestReleaseManifestSHA256) {
		return s, errors.New("Состояние доверия релиза содержит некорректную контрольную сумму манифеста")
	}
	return s, nil
}

func precheckTrustState0158(path, rootFP string, policyEpoch uint64, releaseVersion, releaseManifestSHA256 string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("Для проверки релиза v2 необходимо постоянное состояние --trust-state или LAUNCHER_RELEASE_TRUST_STATE_FILE")
	}
	s, err := loadTrustState0158(path)
	if err != nil {
		return err
	}
	if s.RootFingerprint != "" && !strings.EqualFold(s.RootFingerprint, rootFP) {
		return errors.New("Состояние доверия к релизу привязано к другому корневому ключу")
	}
	if policyEpoch < s.HighestTrustEpoch {
		return fmt.Errorf("Откат эпохи доверия: политика=%d, принятая эпоха=%d", policyEpoch, s.HighestTrustEpoch)
	}
	if s.HighestRelease != "" {
		cur, ok1 := parseVersionTriple0158(releaseVersion)
		old, ok2 := parseVersionTriple0158(s.HighestRelease)
		if !ok1 || !ok2 {
			return errors.New("В состоянии защиты от отката указана некорректная версия выпуска")
		}
		cmp := compareVersionTriple0158(cur, old)
		if cmp < 0 {
			return fmt.Errorf("Откат релиза заблокирован: релиз=%s, принятая версия=%s", releaseVersion, s.HighestRelease)
		}
		if cmp == 0 && s.HighestReleaseManifestSHA256 != "" && !strings.EqualFold(s.HighestReleaseManifestSHA256, releaseManifestSHA256) {
			return fmt.Errorf("Несовпадение манифеста релиза той же версии: релиз=%s, принятый SHA-256=%s, SHA-256 кандидата=%s", releaseVersion, s.HighestReleaseManifestSHA256, strings.ToLower(releaseManifestSHA256))
		}
	}
	return nil
}

func commitTrustState0158(ctx releaseVerificationV2Context) error {
	s, err := loadTrustState0158(ctx.StatePath)
	if err != nil {
		return err
	}
	if s.RootFingerprint != "" && !strings.EqualFold(s.RootFingerprint, ctx.RootFingerprint) {
		return errors.New("Состояние доверия к релизу привязано к другому корневому ключу")
	}
	if ctx.Policy.Epoch < s.HighestTrustEpoch {
		return fmt.Errorf("Откат эпохи доверия при фиксации состояния: политика=%d, принятая эпоха=%d", ctx.Policy.Epoch, s.HighestTrustEpoch)
	}
	if err := precheckTrustState0158(ctx.StatePath, ctx.RootFingerprint, ctx.Policy.Epoch, ctx.Envelope.ReleaseVersion, ctx.Envelope.ReleaseManifestSHA256); err != nil {
		return err
	}
	if ctx.Policy.Epoch > s.HighestTrustEpoch {
		s.HighestTrustEpoch = ctx.Policy.Epoch
	}
	if s.HighestRelease == "" {
		s.HighestRelease = ctx.Envelope.ReleaseVersion
		s.HighestReleaseManifestSHA256 = strings.ToLower(ctx.Envelope.ReleaseManifestSHA256)
	} else if a, ok := parseVersionTriple0158(ctx.Envelope.ReleaseVersion); ok {
		if b, ok := parseVersionTriple0158(s.HighestRelease); ok {
			cmp := compareVersionTriple0158(a, b)
			if cmp > 0 {
				s.HighestRelease = ctx.Envelope.ReleaseVersion
				s.HighestReleaseManifestSHA256 = strings.ToLower(ctx.Envelope.ReleaseManifestSHA256)
			} else if cmp == 0 && s.HighestReleaseManifestSHA256 == "" {
				s.HighestReleaseManifestSHA256 = strings.ToLower(ctx.Envelope.ReleaseManifestSHA256)
			}
		}
	}
	s.SchemaVersion, s.TrustDomain, s.RootFingerprint = releaseTrustStateSchema01510, releaseTrustDomain0158, ctx.RootFingerprint
	s.LastKeyFingerprint = ctx.Envelope.KeyFingerprint
	s.StateRevision++
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeJSONFileAtomicMode(ctx.StatePath, s, 0o600)
}

func verifyReleaseSignatureV20158(dir, rootPublicKeyPath, trustStatePath, currentPolicyPath string) (releaseVerificationV2Context, error) {
	resolvedRoot := strings.TrimSpace(rootPublicKeyPath)
	if resolvedRoot == "" {
		resolvedRoot = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE"))
	}
	if resolvedRoot == "" {
		resolvedRoot = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE"))
	}
	if resolvedRoot == "" {
		return releaseVerificationV2Context{}, errors.New("Для проверки релиза v2 требуется внешний корневой открытый ключ")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, resolvedRoot); err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Ошибка корневого доверенного ключа: %w", err)
	}
	if strings.TrimSpace(trustStatePath) == "" {
		return releaseVerificationV2Context{}, errors.New("Для проверки релиза v2 необходимо постоянное состояние --trust-state или LAUNCHER_RELEASE_TRUST_STATE_FILE")
	}
	if err := releasekeypaths.OutsideBundleState(dir, trustStatePath); err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Ошибка состояния доверия: %w", err)
	}
	currentPolicyPath = strings.TrimSpace(currentPolicyPath)
	if currentPolicyPath == "" {
		currentPolicyPath = strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_TRUST_POLICY_FILE"))
	}
	if currentPolicyPath == "" {
		return releaseVerificationV2Context{}, errors.New("для проверки выпуска v2 требуется внешняя текущая политика доверия, заданная через --trust-policy или LAUNCHER_RELEASE_TRUST_POLICY_FILE")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, currentPolicyPath); err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Текущая политика доверия: %w", err)
	}

	now := time.Now().UTC()
	embeddedPolicy, err := loadReleaseTrustPolicy0158(filepath.Join(dir, releaseTrustPolicyFile0158))
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	rootFP, err := verifyReleaseTrustPolicy0158(embeddedPolicy, resolvedRoot, now, false)
	if err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Ошибка встроенной политики доверия: %w", err)
	}
	currentPolicy, err := loadReleaseTrustPolicy0158(currentPolicyPath)
	if err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Текущая политика доверия: %w", err)
	}
	currentRootFP, err := verifyReleaseTrustPolicy0158(currentPolicy, resolvedRoot, now, true)
	if err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Текущая политика доверия: %w", err)
	}
	if !strings.EqualFold(rootFP, currentRootFP) {
		return releaseVerificationV2Context{}, errors.New("Встроенная и текущая политики доверия используют разные корневые ключи")
	}
	if currentPolicy.Epoch < embeddedPolicy.Epoch {
		return releaseVerificationV2Context{}, fmt.Errorf("Откат текущей политики доверия: текущая эпоха=%d, эпоха релиза=%d", currentPolicy.Epoch, embeddedPolicy.Epoch)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	var env releaseSignatureEnvelopeV2
	if err := json.Unmarshal(raw, &env); err != nil {
		return releaseVerificationV2Context{}, err
	}
	if env.SchemaVersion != releaseSignatureSchema0158 || env.TrustDomain != releaseTrustDomain0158 || env.Algorithm != "Ed25519" || env.SignedFile != "SHA256SUMS" {
		return releaseVerificationV2Context{}, errors.New("SHA256SUMS.sig не является подписанным пакетом проверки выпуска версии 2")
	}
	if env.TrustEpoch != embeddedPolicy.Epoch {
		return releaseVerificationV2Context{}, errors.New("Эпоха доверия trustEpoch в подписи выпуска не совпадает со встроенной политикой")
	}
	signedAt, err := time.Parse(time.RFC3339Nano, env.SignedAt)
	if err == nil {
		if issued, e := time.Parse(time.RFC3339Nano, embeddedPolicy.IssuedAt); e != nil || signedAt.Before(issued.Add(-5*time.Minute)) {
			err = errors.New("Подпись создана до вступления политики доверия в силу")
		}
		if embeddedPolicy.ExpiresAt != "" {
			if expires, e := time.Parse(time.RFC3339Nano, embeddedPolicy.ExpiresAt); e != nil || !signedAt.Before(expires) {
				err = errors.New("Подпись находится вне срока действия политики доверия")
			}
		}
	}
	if err != nil || signedAt.After(now.Add(5*time.Minute)) {
		return releaseVerificationV2Context{}, errors.New("Некорректное значение: подпись релиза signedAt")
	}

	// Политика на момент выпуска должна указывать, что подписант активен. Текущая политика
	// может сохранять статус active/verify-only, но более поздний отзыв имеет приоритет.
	embeddedKey, err := trustedReleaseKeyRecord0158(embeddedPolicy, env.KeyID, env.KeyFingerprint)
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	if embeddedKey.Status != "active" {
		return releaseVerificationV2Context{}, fmt.Errorf("Подписант не был активен на момент выпуска релиза: %s", embeddedKey.Status)
	}
	pub, err := findTrustedReleaseKey0158(currentPolicy, env.KeyID, env.KeyFingerprint, signedAt)
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	if !strings.EqualFold(embeddedKey.PublicKey, hex.EncodeToString(pub)) {
		return releaseVerificationV2Context{}, errors.New("Материал ключа релиза изменился между встроенной и текущей политиками доверия")
	}

	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	sum := sha256.Sum256(sums)
	if !strings.EqualFold(env.SHA256, hex.EncodeToString(sum[:])) {
		return releaseVerificationV2Context{}, errors.New("Несовпадение: контрольная сумма SHA256SUMS для выпуска v2")
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	manifestSum := sha256.Sum256(manifestRaw)
	if !strings.EqualFold(env.ReleaseManifestSHA256, hex.EncodeToString(manifestSum[:])) {
		return releaseVerificationV2Context{}, errors.New("Несовпадение: контрольная сумма RELEASE_MANIFEST для выпуска v2")
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return releaseVerificationV2Context{}, err
	}
	if env.ReleaseVersion != m.Version {
		return releaseVerificationV2Context{}, errors.New("Несовпадение: привязка версии выпуска v2")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return releaseVerificationV2Context{}, errors.New("Некорректное значение: кодировка подписи выпуска v2")
	}
	payload, err := releaseSignaturePayload0158(env)
	if err != nil {
		return releaseVerificationV2Context{}, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return releaseVerificationV2Context{}, errors.New("Проверка подписи Ed25519 выпуска v2 завершилась ошибкой")
	}
	if err := verifyDetachedFileWithKey(filepath.Join(dir, "PROVENANCE.json"), filepath.Join(dir, "PROVENANCE.json.sig"), pub); err != nil {
		return releaseVerificationV2Context{}, fmt.Errorf("Сведения о происхождении релиза v2: %w", err)
	}
	if err := precheckTrustState0158(trustStatePath, rootFP, currentPolicy.Epoch, env.ReleaseVersion, env.ReleaseManifestSHA256); err != nil {
		return releaseVerificationV2Context{}, err
	}
	return releaseVerificationV2Context{Policy: currentPolicy, Envelope: env, RootFingerprint: rootFP, StatePath: trustStatePath}, nil
}

func trustedReleaseKeyRecord0158(policy releaseTrustPolicy0158, id, fp string) (releaseTrustKey0158, error) {
	for _, k := range policy.Keys {
		if k.ID == id && strings.EqualFold(k.Fingerprint, fp) {
			return k, nil
		}
	}
	return releaseTrustKey0158{}, fmt.Errorf("ключ выпуска отсутствует в политике доверия: id=%s fingerprint=%s", id, fp)
}

func signReleaseBundleV20158(dir string, privateKey ed25519.PrivateKey) error {
	policy, err := loadReleaseTrustPolicy0158(filepath.Join(dir, releaseTrustPolicyFile0158))
	if err != nil {
		return err
	}
	pub := privateKey.Public().(ed25519.PublicKey)
	fp := fingerprintEd255190158(pub)
	var key releaseTrustKey0158
	found := false
	for _, k := range policy.Keys {
		if strings.EqualFold(k.Fingerprint, fp) {
			key = k
			found = true
			break
		}
	}
	if !found || key.Status != "active" {
		return errors.New("ключ подписи не является активным ключом выпуска в текущей политике доверия")
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sumsDigest := sha256.Sum256(sums)
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return err
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return err
	}
	env := releaseSignatureEnvelopeV2{SchemaVersion: releaseSignatureSchema0158, TrustDomain: releaseTrustDomain0158, Algorithm: "Ed25519", SignedFile: "SHA256SUMS", SHA256: hex.EncodeToString(sumsDigest[:]), ReleaseManifestSHA256: hex.EncodeToString(manifestDigest[:]), ReleaseVersion: manifest.Version, TrustEpoch: policy.Epoch, KeyID: key.ID, KeyFingerprint: fp, SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	payload, err := releaseSignaturePayload0158(env)
	if err != nil {
		return err
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return signDetachedFileWithKey(filepath.Join(dir, "PROVENANCE.json"), filepath.Join(dir, "PROVENANCE.json.sig"), privateKey)
}

func exportReleaseTrustPolicy0158(args []string) (map[string]any, error) {
	dir := securityRegistryDir(args)
	reg, err := loadKeyRegistry(dir)
	if err != nil {
		return nil, err
	}
	if reg.TrustEpoch == 0 {
		return nil, errors.New("В реестре trustEpoch=0; сначала создайте или смените ключ подписи выпуска")
	}
	rootPrivatePath := flagValue(args, "--root-private-key", strings.TrimSpace(os.Getenv("LAUNCHER_RELEASE_ROOT_PRIVATE_KEY_FILE")))
	if rootPrivatePath == "" {
		return nil, errors.New("для команды trust-policy требуется --root-private-key")
	}
	rootPriv, err := loadEd25519PrivateKey(rootPrivatePath)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresHours := 24 * 365
	if v := flagValue(args, "--expires-hours", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, errors.New("Некорректное значение: --expires-hours")
		}
		expiresHours = n
	}
	policy := releaseTrustPolicy0158{SchemaVersion: releaseSignatureSchema0158, TrustDomain: releaseTrustDomain0158, Epoch: reg.TrustEpoch, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Duration(expiresHours) * time.Hour).Format(time.RFC3339Nano)}
	for _, rec := range reg.Keys {
		if rec.Purpose != "release-signing" {
			continue
		}
		pub, err := loadEd25519PublicKey(rec.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("Ключ %s: %w", rec.ID, err)
		}
		policy.Keys = append(policy.Keys, releaseTrustKey0158{ID: rec.ID, Purpose: rec.Purpose, Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Fingerprint: rec.Fingerprint, Status: rec.Status, NotBefore: rec.CreatedAt, RetiredAt: rec.RetiredAt, RevokedAt: rec.RevokedAt, ReplacedBy: rec.ReplacedBy})
	}
	if len(policy.Keys) == 0 {
		return nil, errors.New("В реестре отсутствуют ключи подписи выпуска")
	}
	active := 0
	for _, k := range policy.Keys {
		if k.Status == "active" {
			active++
		}
	}
	if active == 0 {
		return nil, errors.New("В реестре отсутствует активный ключ подписи выпуска")
	}
	sort.Slice(policy.Keys, func(i, j int) bool { return policy.Keys[i].ID < policy.Keys[j].ID })
	payload, err := releaseTrustPolicyPayload0158(policy)
	if err != nil {
		return nil, err
	}
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	rootFP := fingerprintEd255190158(rootPub)
	for _, k := range policy.Keys {
		if strings.EqualFold(k.Fingerprint, rootFP) {
			return nil, errors.New("Автономный корневой ключ не может одновременно служить ключом подписи выпуска")
		}
	}
	policy.RootSignature = &releaseTrustRootSignature0158{Algorithm: "Ed25519", RootFingerprint: rootFP, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(rootPriv, payload)), SignedAt: now.Format(time.RFC3339Nano)}
	out := flagValue(args, "--policy-out", releaseTrustPolicyFile0158)
	if err := writeJSONFile(out, policy); err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": releaseSignatureSchema0158, "toolVersion": version, "status": "trust-policy-exported", "trustEpoch": policy.Epoch, "rootFingerprint": rootFP, "keys": len(policy.Keys), "output": out}, nil
}

func verifyTrustPolicyCommand0158(args []string) (map[string]any, error) {
	path := flagValue(args, "--path", releaseTrustPolicyFile0158)
	p, err := loadReleaseTrustPolicy0158(path)
	if err != nil {
		return nil, err
	}
	root := flagValue(args, "--root-public-key", flagValue(args, "--public-key", ""))
	fp, err := verifyReleaseTrustPolicy0158(p, root, time.Now().UTC(), true)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": releaseSignatureSchema0158, "toolVersion": version, "status": "verified", "trustEpoch": p.Epoch, "rootFingerprint": fp, "keys": len(p.Keys)}, nil
}
