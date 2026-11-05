package main

// Политика совместимости Guard v1: внешний ключ Ed25519 разрешает строго тот код,
// который оператор допускает в JVM Minecraft. Политика проверяется при установке И
// непосредственно перед игрой. Отсутствующая, истёкшая или откатившаяся политика
// приводит к отказу для профилей с обязательной совместимостью Guard.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	guardCompatDomain0502      = "NeverLauncher-Guard-Compatibility-v1\n"
	guardCompatSchema0502      = "launcher.guard-compatibility.v1"
	guardCompatPolicyFile0502  = ".launcher/guard/compatibility.json"
	guardCompatFloorFile0502   = ".launcher/guard/accepted.json"
	guardCompatKeyEnv0502      = "LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE"
	guardCompatRequiredEnv0502 = "LAUNCHER_GUARD_COMPAT_REQUIRED"
)

type guardCompatEnvelope0502 struct {
	Schema    string `json:"schemaVersion"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type guardCompatArtifact0502 struct {
	Kind   string `json:"kind"` // mod, java-agent, java-plugin, native-library, loader-library
	Path   string `json:"path"` // client-root relative, slash-normalized
	SHA256 string `json:"sha256"`
}
type guardCompatTransform0502 struct {
	ID          string `json:"id"`
	OwnerSHA256 string `json:"ownerSha256"`
}
type guardCompatClassBytes0504 struct {
	Class  string `json:"class"`
	SHA256 string `json:"sha256"`
}
type guardCompatExternalNative05010 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type guardCompatPolicy0502 struct {
	Schema                string                           `json:"schemaVersion"`
	ProjectID             string                           `json:"projectId"`
	Minecraft             string                           `json:"minecraft"`
	Loader                string                           `json:"loader"`
	Epoch                 uint64                           `json:"epoch"`
	IssuedAt              int64                            `json:"issuedAt"`
	ExpiresAt             int64                            `json:"expiresAt"`
	Artifacts             []guardCompatArtifact0502        `json:"artifacts"`
	Transformations       []guardCompatTransform0502       `json:"transformations"`
	RevokedDigests        []string                         `json:"revokedDigests"`
	RevokedTransforms     []string                         `json:"revokedTransformations"`
	LoaderClassBytes      []guardCompatClassBytes0504      `json:"loaderClassBytes,omitempty"`
	ExternalNativeModules []guardCompatExternalNative05010 `json:"externalNativeModules,omitempty"`
}
type guardCompatFloor0502 struct {
	Epoch      uint64 `json:"epoch"`
	Digest     string `json:"digest"`
	RootSHA256 string `json:"rootSha256"`
}
type guardCompatVerified0502 struct {
	Policy     guardCompatPolicy0502
	Digest     string
	RootSHA256 string
}

func guardCompatDecode0502[T any](data []byte, out *T) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("Guard compatibility JSON trailing content")
	}
	return nil
}
func guardCompatHex0502(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func guardCompatRel0502(rel string) bool {
	if rel == "" || strings.ContainsAny(rel, "\\:\x00\r\n") || strings.HasPrefix(rel, "/") || strings.Contains(rel, "//") || strings.TrimSpace(rel) != rel {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func guardCompatPublicKey0502(root, keyFile string) (ed25519.PublicKey, string, error) {
	if keyFile == "" {
		return nil, "", fmt.Errorf("Для совместимости Guard требуется внешний параметр %s", guardCompatKeyEnv0502)
	}
	if err := trustedAnchor0306(root, keyFile); err != nil {
		return nil, "", err
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > 1024 {
		return nil, "", errors.New("Открытый ключ совместимости Guard превышает допустимый размер")
	}
	text := strings.TrimSpace(string(raw))
	var b []byte
	if b, err = hex.DecodeString(text); err != nil || len(b) != ed25519.PublicKeySize {
		b, err = base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, "", errors.New("Для «Guard compatibility key» требуется: «32-byte hex or base64»")
		}
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, "", errors.New("Некорректное значение: длина открытого ключа Ed25519 для совместимости Guard")
	}
	hash := sha256.Sum256(b)
	return ed25519.PublicKey(b), hex.EncodeToString(hash[:]), nil
}
func guardCompatVerifiedBytes0502(root, keyFile string, raw []byte, now time.Time) (guardCompatVerified0502, error) {
	var result guardCompatVerified0502
	if len(raw) > 256*1024 {
		return result, errors.New("Контейнер совместимости Guard превышает допустимый размер")
	}
	key, rootDigest, err := guardCompatPublicKey0502(root, keyFile)
	if err != nil {
		return result, err
	}
	var envelope guardCompatEnvelope0502
	if err = guardCompatDecode0502(raw, &envelope); err != nil {
		return result, err
	}
	if envelope.Schema != guardCompatSchema0502 {
		return result, errors.New("Неизвестное значение: контейнер совместимости Guard")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) > 192*1024 || len(payload) == 0 {
		return result, errors.New("Некорректные данные политики совместимости Guard")
	}
	sig, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return result, errors.New("Недопустимая длина подписи совместимости Guard")
	}
	if !ed25519.Verify(key, append([]byte(guardCompatDomain0502), payload...), sig) {
		return result, errors.New("Проверка подписи совместимости Guard завершилась ошибкой")
	}
	var p guardCompatPolicy0502
	if err = guardCompatDecode0502(payload, &p); err != nil {
		return result, err
	}
	if err = p.validate0502(now); err != nil {
		return result, err
	}
	digest := sha256.Sum256(payload)
	return guardCompatVerified0502{Policy: p, Digest: hex.EncodeToString(digest[:]), RootSHA256: rootDigest}, nil
}
func (p guardCompatPolicy0502) validate0502(now time.Time) error {
	if p.Schema != guardCompatSchema0502 || p.Epoch == 0 || p.ProjectID == "" || p.Minecraft == "" || p.Loader == "" ||
		len(p.ProjectID) > 128 || len(p.Minecraft) > 128 || len(p.Loader) > 64 {
		return errors.New("Некорректная область действия политики совместимости Guard")
	}
	current := now.Unix()
	if p.IssuedAt > current+300 || p.ExpiresAt <= current || p.IssuedAt <= 0 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 90*86400 {
		return errors.New("Guard compatibility policy expired, future-issued or exceeds validity")
	}
	if len(p.Artifacts) > 4096 || len(p.Transformations) > 4096 || len(p.LoaderClassBytes) > 4096 || len(p.ExternalNativeModules) > 64 || len(p.RevokedDigests) > 4096 || len(p.RevokedTransforms) > 4096 {
		return errors.New("Список совместимости Guard превышает допустимый размер")
	}
	seen := map[string]bool{}
	digests := map[string]bool{}
	for _, a := range p.Artifacts {
		switch a.Kind {
		case "mod", "java-agent", "java-plugin", "native-library", "loader-library":
		default:
			return fmt.Errorf("Неизвестное значение: тип артефакта совместимости Guard %q", a.Kind)
		}
		if !guardCompatRel0502(a.Path) || !guardCompatHex0502(a.SHA256) {
			return errors.New("Некорректный путь или дайджест артефакта совместимости Guard")
		}
		key := a.Kind + ":" + strings.ToLower(a.Path)
		if seen[key] {
			return errors.New("Guard compatibility duplicate artifact")
		}
		seen[key] = true
		if a.Kind == "java-plugin" {
			digests[a.SHA256] = true
		}
	}
	for _, t := range p.Transformations {
		if t.ID == "" || len(t.ID) > 256 || strings.ContainsAny(t.ID, "\x00\r\n") || !guardCompatHex0502(t.OwnerSHA256) || seen["transform:"+t.ID] {
			return errors.New("Guard compatibility transformation invalid/duplicated")
		}
		if !digests[t.OwnerSHA256] {
			return errors.New("Guard compatibility transformation owner not authorized")
		}
		seen["transform:"+t.ID] = true
	}
	for _, cls := range p.LoaderClassBytes {
		if !guardCompatClassName0504(cls.Class) || !guardCompatHex0502(cls.SHA256) || seen["loader-class:"+cls.Class] {
			return errors.New("Guard loader class-byte binding invalid/duplicated")
		}
		seen["loader-class:"+cls.Class] = true
	}
	for _, external := range p.ExternalNativeModules {
		if !guardCompatExternalNativePath05010(external.Path) || !guardCompatHex0502(external.SHA256) || seen["external:"+external.Path] {
			return errors.New("Guard external native module path/digest invalid or duplicated")
		}
		seen["external:"+external.Path] = true
	}
	for _, s := range p.RevokedDigests {
		if !guardCompatHex0502(s) || seen["revoked:"+s] {
			return errors.New("Guard compatibility revoked digest invalid/duplicated")
		}
		seen["revoked:"+s] = true
	}
	for _, s := range p.RevokedTransforms {
		if s == "" || len(s) > 256 || seen["revoked-transform:"+s] {
			return errors.New("Guard compatibility revoked transformation invalid/duplicated")
		}
		seen["revoked-transform:"+s] = true
	}
	return nil
}
func guardCompatExternalNativePath05010(path string) bool {
	if len(path) > 4096 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n") ||
		strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/") {
		return false
	}
	for _, component := range strings.Split(path, "/")[1:] {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".so") || strings.Contains(lower, ".so.")
}
func guardCompatExternalNativeHash05010(path string) (string, error) {
	if !guardCompatExternalNativePath05010(path) {
		return "", errors.New("Некорректное значение: внешний нативный путь")
	}
	current := "/"
	for _, component := range strings.Split(path, "/")[1:] {
		current = filepath.Join(current, component)
		stat, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if stat.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("external native module symlink rejected")
		}
	}
	stat, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 512<<20 {
		return "", errors.New("Некорректное значение: внешний нативный модуль")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err = io.Copy(sum, io.LimitReader(f, (512<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
func guardCompatPath0502(root, rel string) (string, error) {
	if !guardCompatRel0502(rel) {
		return "", errors.New("Некорректное значение: «Guard compatibility relative path»")
	}
	return secureClientDestination(root, rel)
}
func guardCompatRead0502(root, rel string, max int64) ([]byte, error) {
	path, err := guardCompatPath0502(root, rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("Guard compatibility unsafe file %s", rel)
	}
	return os.ReadFile(path)
}
func guardCompatFloorRead0502(root string) (*guardCompatFloor0502, error) {
	data, err := guardCompatRead0502(root, guardCompatFloorFile0502, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var floor guardCompatFloor0502
	if err = guardCompatDecode0502(data, &floor); err != nil {
		return nil, err
	}
	if floor.Epoch == 0 || !guardCompatHex0502(floor.Digest) || !guardCompatHex0502(floor.RootSHA256) {
		return nil, errors.New("Состояние защиты от отката политики совместимости Guard повреждено")
	}
	return &floor, nil
}
func guardCompatAgainstFloor0502(root string, v guardCompatVerified0502) error {
	floor, err := guardCompatFloorRead0502(root)
	if err != nil {
		return err
	}
	if floor != nil && (floor.RootSHA256 != v.RootSHA256 || floor.Epoch > v.Policy.Epoch || (floor.Epoch == v.Policy.Epoch && floor.Digest != v.Digest)) {
		return errors.New("Обнаружено изменение корня доверия, откат или противоречивое состояние политики совместимости Guard")
	}
	return nil
}
func guardCompatInstall0502(root, policyFile, keyFile string) error {
	st, err := os.Lstat(policyFile)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 256*1024 {
		return errors.New("Небезопасный объект: входные данные политики совместимости Guard")
	}
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		return err
	}
	// Атомарный mkdir — межплатформенный барьер единственного писателя. После сбоя остаётся блокировка
	// с отказом по умолчанию, требующая восстановления оператором, а не гонка старых эпох.
	lock, err := guardCompatPath0502(root, ".launcher/guard/.install-lock")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(lock), 0700); err != nil {
		return err
	}
	if err = os.Mkdir(lock, 0700); err != nil {
		return fmt.Errorf("Guard compatibility concurrent/stale policy install lock: %w", err)
	}
	defer os.Remove(lock)
	v, err := guardCompatVerifiedBytes0502(root, keyFile, raw, time.Now())
	if err != nil {
		return err
	}
	if err = guardCompatAgainstFloor0502(root, v); err != nil {
		return err
	}
	if err = guardCompatArchiveIncoming05011(root, keyFile, raw, v); err != nil {
		return err
	}
	active, err := guardCompatPath0502(root, guardCompatPolicyFile0502)
	if err != nil {
		return err
	}
	floor, err := guardCompatPath0502(root, guardCompatFloorFile0502)
	if err != nil {
		return err
	}
	state, _ := json.Marshal(guardCompatFloor0502{Epoch: v.Policy.Epoch, Digest: v.Digest, RootSHA256: v.RootSHA256})
	// СНАЧАЛА сохраните минимальную допустимую эпоху: после сбоя старая политика отклоняется, а не
	// принимается ошибочно. Повторная установка той же подписанной эпохи завершает восстановление.
	if err = trustedAtomic0306(floor, append(state, '\n')); err != nil {
		return err
	}
	return trustedAtomic0306(active, raw)
}
func guardCompatLoad0502(root, keyFile string) (*guardCompatVerified0502, error) {
	raw, err := guardCompatRead0502(root, guardCompatPolicyFile0502, 256*1024)
	if errors.Is(err, os.ErrNotExist) {
		floor, ferr := guardCompatFloorRead0502(root)
		if ferr != nil {
			return nil, ferr
		}
		if floor != nil || os.Getenv(guardCompatRequiredEnv0502) == "1" {
			return nil, errors.New("Отсутствует: обязательная политика совместимости Guard")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := guardCompatVerifiedBytes0502(root, keyFile, raw, time.Now())
	if err != nil {
		return nil, err
	}
	floor, err := guardCompatFloorRead0502(root)
	if err != nil {
		return nil, err
	}
	if floor == nil {
		return nil, errors.New("Отсутствует: состояние принятой эпохи совместимости Guard")
	}
	if err = guardCompatAgainstFloor0502(root, v); err != nil {
		return nil, err
	}
	return &v, nil
}
func guardCompatHashFile0502(root, rel string) (string, error) {
	path, err := guardCompatPath0502(root, rel)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > 512<<20 {
		return "", fmt.Errorf("Небезопасный объект: данные совместимости Guard %s", rel)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := sha256.New()
	if _, err = io.Copy(d, io.LimitReader(f, (512<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(d.Sum(nil)), nil
}
func guardCompatRelative0502(root, full string) (string, error) {
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if !guardCompatRel0502(rel) {
		return "", fmt.Errorf("Guard compatibility path outside client: %s", full)
	}
	return rel, nil
}
func guardCompatValidateLaunch0502(root, project, minecraft, loader string, agents, plugins []string) error {
	return guardCompatValidateLaunchWithKey05011(root, strings.TrimSpace(os.Getenv(guardCompatKeyEnv0502)), project, minecraft, loader, agents, plugins)
}
func guardCompatValidateLaunchWithKey05011(root, key, project, minecraft, loader string, agents, plugins []string) error {
	v, err := guardCompatLoad0502(root, key)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	} // явный устаревший режим без защиты
	p := v.Policy
	for _, name := range []string{"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"} {
		if opts := strings.ToLower(os.Getenv(name)); strings.Contains(opts, "-javaagent:") || strings.Contains(opts, "-agentpath:") || strings.Contains(opts, "-agentlib:") || strings.Contains(opts, "-xrunjdwp:") {
			return fmt.Errorf("Guard compatibility rejected injected JVM options from %s", name)
		}
	}
	if p.ProjectID != project || p.Minecraft != minecraft || !strings.EqualFold(p.Loader, loader) {
		return errors.New("Область действия политики совместимости Guard не соответствует установленной игре")
	}
	authorized := map[string]guardCompatArtifact0502{}
	revoked := map[string]bool{}
	revokedTransform := map[string]bool{}
	for _, hash := range p.RevokedDigests {
		revoked[hash] = true
	}
	for _, id := range p.RevokedTransforms {
		revokedTransform[id] = true
	}
	for _, a := range p.Artifacts {
		if revoked[a.SHA256] {
			return fmt.Errorf("Guard compatibility artifact revoked: %s", a.Path)
		}
		actual, err := guardCompatHashFile0502(root, a.Path)
		if err != nil {
			return fmt.Errorf("Guard compatibility missing %s: %w", a.Path, err)
		}
		if actual != a.SHA256 {
			return fmt.Errorf("Несовпадение: «Guard compatibility digest»: %s", a.Path)
		}
		authorized[a.Kind+":"+strings.ToLower(a.Path)] = a
	}
	for _, ext := range p.ExternalNativeModules {
		if revoked[ext.SHA256] {
			return fmt.Errorf("Guard external native module revoked: %s", ext.Path)
		}
		actual, err := guardCompatExternalNativeHash05010(ext.Path)
		if err != nil {
			return fmt.Errorf("Недоступно: внешний нативный модуль Guard: %w", err)
		}
		if actual != ext.SHA256 {
			return fmt.Errorf("Обнаружено изменение: внешний нативный модуль Guard: %s", ext.Path)
		}
	}
	for _, tr := range p.Transformations {
		if revokedTransform[tr.ID] || revoked[tr.OwnerSHA256] {
			return fmt.Errorf("Guard compatibility transformation revoked: %s", tr.ID)
		}
	}
	required := map[string]bool{}
	for _, a := range agents {
		rel, e := guardCompatRelative0502(root, a)
		if e != nil {
			return e
		}
		required["java-agent:"+strings.ToLower(rel)] = true
	}
	for _, a := range plugins {
		rel, e := guardCompatRelative0502(root, a)
		if e != nil {
			return e
		}
		required["java-plugin:"+strings.ToLower(rel)] = true
	}
	for _, folder := range []struct {
		path, kind string
		extensions []string
	}{{"mods", "mod", []string{".jar"}}, {"natives", "native-library", []string{".dll", ".so", ".dylib", ".jnilib"}}} {
		dir, err := guardCompatPath0502(root, folder.path)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("Запрещено: «Guard compatibility symlink»: %s", path)
			}
			if entry.IsDir() {
				return nil
			}
			for _, ext := range folder.extensions {
				if strings.HasSuffix(strings.ToLower(entry.Name()), ext) {
					rel, e := guardCompatRelative0502(root, path)
					if e != nil {
						return e
					}
					required[folder.kind+":"+strings.ToLower(rel)] = true
					break
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for wanted := range required {
		if _, ok := authorized[wanted]; !ok {
			return fmt.Errorf("Guard compatibility unauthorized code %s", wanted)
		}
	}
	return nil
}
func guardCompatInspect0502(root, key string) (map[string]any, error) {
	v, err := guardCompatLoad0502(root, key)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("Политика совместимости Guard не установлена")
	}
	kinds := map[string]int{}
	for _, a := range v.Policy.Artifacts {
		kinds[a.Kind]++
	}
	return map[string]any{"valid": true, "epoch": v.Policy.Epoch, "policySha256": v.Digest, "projectId": v.Policy.ProjectID, "minecraft": v.Policy.Minecraft, "loader": v.Policy.Loader, "artifactCounts": kinds, "transformations": len(v.Policy.Transformations), "revokedDigests": len(v.Policy.RevokedDigests)}, nil
}
func handleGuardCompat0502(args []string) error {
	if len(args) == 0 {
		return errors.New("Требуется: guard-policy-install|guard-policy-verify|guard-policy-status|guard-policy-history|guard-policy-diagnose|guard-policy-rollback")
	}
	root := flagValue(args[1:], "--client-dir", "")
	if root == "" {
		return errors.New("Требуется: --client-dir")
	}
	key := flagValue(args[1:], "--public-key", os.Getenv(guardCompatKeyEnv0502))
	switch args[0] {
	case "guard-policy-install", "guard-policy-rollback":
		file := flagValue(args[1:], "--policy", "")
		if file == "" {
			return errors.New("Требуется подписанный файл политики --policy")
		}
		if args[0] == "guard-policy-rollback" {
			if err := guardCompatAuthorizeRollback05011(root, key, file); err != nil {
				return err
			}
		}
		if err := guardCompatInstall0502(root, file, key); err != nil {
			return err
		}
		report, err := guardCompatInspect0502(root, key)
		if err != nil {
			return err
		}
		printJSON(report)
		return nil
	case "guard-policy-status", "guard-policy-history", "guard-policy-diagnose":
		report, err := guardCompatOperation05011(root, key, args)
		if report != nil {
			printJSON(report)
		}
		return err
	case "guard-policy-verify":
		report, err := guardCompatInspect0502(root, key)
		if err != nil {
			return err
		}
		printJSON(report)
		return nil
	default:
		return errors.New("Неизвестная операция политики совместимости Guard")
	}
}
