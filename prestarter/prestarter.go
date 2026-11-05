package prestarter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	ConfigPath      string
	TrustPolicyPath string
	TrustedKey      string
	Root            string
	OfflineDir      string
	Offline         bool
	LaunchProfile   bool
	Username        string
	NoDesktop       bool // проверки и подготовка установки без участия пользователя
}
type manifestIdentity struct {
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Runtime   struct {
		Java struct {
			Major        uint32 `json:"majorVersion"`
			Distribution string `json:"distribution"`
		} `json:"java"`
		Launch struct {
			OfflineMode bool `json:"offlineMode"`
		} `json:"launch"`
	} `json:"runtime"`
}
type javaResult struct {
	JavaExecutable string `json:"javaExecutable"`
	Major          uint32 `json:"majorVersion"`
	Distribution   string `json:"distribution"`
}
type activeRecord struct {
	Generation   uint64 `json:"generation"`
	Digest       string `json:"digest"`
	Platform     string `json:"platform"`
	Release      string `json:"release"`
	ConfigSHA256 string `json:"configSha256"`
}
type switchJournal struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type installer struct {
	root         string
	key          string
	store        *storage
	config       Config
	digest       string
	rawConfig    []byte
	target       Target
	launcherRoot string
	gameRoot     string
}

func Run(ctx context.Context, opts Options) error {
	if opts.ConfigPath == "" || opts.Root == "" {
		return errors.New("Обязательны параметры --config и --root")
	}
	if opts.TrustedKey == "" {
		return errors.New("Требуется встроенный или явно установленный корневой публичный ключ")
	}
	raw, e := os.ReadFile(opts.ConfigPath)
	if e != nil {
		return e
	}
	root, e := safeRoot(opts.Root)
	if e != nil {
		return e
	}
	if e = validateInputRoot(opts.OfflineDir, root); e != nil {
		return e
	}
	// Блокировка устанавливается до принятия доверенного состояния. Конкурирующие процессы не должны создавать гонку эпох политики или отменять отзыв при первом запуске.
	store, e := newStorage(filepath.Join(root, ".launcher-prestarter"), opts.OfflineDir, opts.Offline)
	if e != nil {
		return e
	}
	if e = safeMkdir(store.root); e != nil {
		return e
	}
	lock, e := acquireProcessLock(filepath.Join(store.root, "bootstrap.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	var cfg Config
	var digest string
	var env Envelope
	if e = decodeStrict(raw, &env); e != nil {
		return e
	}
	if env.SchemaVersion == "2.0" {
		policyFile := opts.TrustPolicyPath
		if policyFile == "" {
			policyFile = filepath.Join(store.root, "trust", "active-policy.json")
		}
		policyBytes, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("Для делегированного bootstrap требуется локально установленная политика с подписью корневого ключа: %w", err)
		}
		policy, err := AcceptTrustPolicy(filepath.Join(store.root, "trust"), opts.TrustedKey, policyBytes, time.Now().UTC())
		if err != nil {
			return err
		}
		cfg, digest, e = VerifyEnvelopeWithPolicy(raw, opts.TrustedKey, &policy)
	} else {
		if st, err := readPolicyState02312(filepath.Join(store.root, "trust", "trust-state.json")); err != nil || st.Epoch > 0 {
			return errors.New("После активации делегированного доверия устаревший bootstrap запрещён")
		}
		cfg, digest, e = VerifyEnvelope(raw, opts.TrustedKey)
	}
	if e != nil {
		return e
	}
	if env.SchemaVersion == "2.0" && !strings.EqualFold(cfg.ProfilePublicKey, opts.TrustedKey) {
		return errors.New("Делегированный корневой ключ доверия игры должен совпадать с закреплённым корневым ключом bootstrap")
	}
	target, e := cfg.SelectTarget()
	if e != nil {
		return e
	}
	// На Windows производственный Desktop требует аутентифицированную границу супервизора Guard до запуска игры. Нельзя предоставлять менее защищённый прямой путь CLI, обходящий эту границу.
	if opts.LaunchProfile && runtime.GOOS == "windows" {
		return errors.New("В Windows запуск профиля должен выполняться через Desktop (требуется контроллер Guard)")
	}
	if opts.Username != "" && !validUsername(opts.Username) {
		return errors.New("Недопустимое автономное имя пользователя Minecraft")
	}
	p := &installer{root: root, key: opts.TrustedKey, store: store, config: cfg, digest: digest, rawConfig: raw, target: target, launcherRoot: filepath.Join(root, "launcher"), gameRoot: filepath.Join(root, "profiles", cfg.ProjectID, cfg.ProfileID)}
	if e = safeMkdir(p.launcherRoot); e != nil {
		return e
	}
	if e = safeMkdir(p.gameRoot); e != nil {
		return e
	}
	if e = safeMkdir(store.root); e != nil {
		return e
	}
	// Указатель с двумя слотами служит восстанавливаемым журналом фиксаций. Нельзя запускать бинарники из непроверенного либо частично установленного выпуска.
	if e = p.cleanupInterruptedStages(); e != nil {
		return e
	}
	previous, _ := p.current()
	installed, e := p.installComponents(ctx, previous)
	if e != nil {
		return e
	}
	if e = p.activate(previous, installed); e != nil {
		return e
	}
	if e = p.prepareAndStart(ctx, installed, opts); e != nil {
		// Хеши новых бинарников были верны, но запуск или Managed Java завершились ошибкой. Восстановите предыдущий проверенный активный выпуск с более высоким поколением, чтобы даже сбой во время отката оставался восстанавливаемым.
		if active, currentErr := p.current(); currentErr == nil && active.Release == installed.Release {
			if previous != nil {
				if restoreErr := p.activate(active, *previous); restoreErr != nil {
					return fmt.Errorf("Ошибка bootstrap: %v; не удалось активировать последнюю исправную версию: %w", e, restoreErr)
				}
			} else {
				// При первичной установке нет последнего исправного слота. Не оставляйте активным выпуск, не прошедший проверку, Java или синхронизацию. Проверенные по хешу байты останутся в кэше для дальнейшего восстановления.
				if rollbackErr := p.deactivateFailedFirstRun(active); rollbackErr != nil {
					return fmt.Errorf("Ошибка bootstrap: %v; не удалось откатить первоначальную активацию: %w", e, rollbackErr)
				}
			}
		}
		return e
	}
	return nil
}
func validateInputRoot(offline, root string) error {
	if offline == "" {
		return nil
	}
	abs, e := filepath.Abs(offline)
	if e != nil {
		return e
	}
	if abs == root || strings.HasPrefix(root, abs+string(os.PathSeparator)) {
		return errors.New("Корневой каталог установки не должен находиться внутри автономного источника")
	}
	return nil
}
func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

// Восстановление после аварии удаляет только собственные незафиксированные каталоги подготовки. Зафиксированный активный выпуск никогда не изменяется и не удаляется этой очисткой.
func (p *installer) cleanupInterruptedStages() error {
	releases := filepath.Join(p.launcherRoot, "releases")
	if err := safeMkdir(releases); err != nil {
		return err
	}
	entries, err := os.ReadDir(releases)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".incomplete-") {
			continue
		}
		path := filepath.Join(releases, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Небезопасная запись в промежуточной области прерванного bootstrap")
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return syncDir(releases)
}

func (p *installer) installComponents(ctx context.Context, previous *activeRecord) (activeRecord, error) {
	platform := p.target.OS + "-" + p.target.Arch
	rel := p.digest + "-" + platform
	record := activeRecord{Digest: p.digest, Platform: platform, Release: rel, ConfigSHA256: hexDigest(p.rawConfig)}
	releaseDir := filepath.Join(p.launcherRoot, "releases", rel)
	if e := safeMkdir(filepath.Dir(releaseDir)); e != nil {
		return record, e
	}
	if p.releaseValid(record) {
		return record, nil
	}
	if _, e := os.Lstat(releaseDir); e == nil {
		if e = os.Rename(releaseDir, releaseDir+".broken-"+strconv.FormatInt(time.Now().UnixNano(), 10)); e != nil {
			return record, e
		}
	}
	stage, e := os.MkdirTemp(filepath.Dir(releaseDir), ".incomplete-")
	if e != nil {
		return record, e
	}
	defer os.RemoveAll(stage)
	for _, component := range p.target.Components {
		source, e := p.store.artifact(ctx, component.Artifact, filepath.Join("components", ComponentName(component.Name)))
		if e != nil {
			return record, fmt.Errorf("Компонент %s: %w", component.Name, e)
		}
		destination := filepath.Join(stage, ComponentName(component.Name))
		if e = durableCopy(source, destination, component.Artifact, true); e != nil {
			return record, e
		}
	}
	if e := atomicSmallWrite(filepath.Join(stage, "signed-config.json"), p.rawConfig); e != nil {
		return record, e
	}
	if e := syncDir(stage); e != nil {
		return record, e
	}
	if e := os.Rename(stage, releaseDir); e != nil {
		return record, e
	}
	if e := syncDir(filepath.Dir(releaseDir)); e != nil {
		return record, e
	}
	if !p.releaseValid(record) {
		return record, errors.New("Установленный выпуск компонента не прошёл проверку после установки")
	}
	return record, nil
}
func hexDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (p *installer) configTrustEpoch() uint64 {
	var e Envelope
	_ = decodeStrict(p.rawConfig, &e)
	if e.SchemaVersion == "2.0" {
		return e.TrustEpoch
	}
	return 0
}
func (p *installer) verifyConfig(raw []byte) (Config, string, error) {
	var e Envelope
	if err := decodeStrict(raw, &e); err != nil {
		return Config{}, "", err
	}
	if e.SchemaVersion == "2.0" {
		policyRaw, err := os.ReadFile(filepath.Join(p.store.root, "trust", "active-policy.json"))
		if err != nil {
			return Config{}, "", err
		}
		policy, _, err := VerifyTrustPolicy(policyRaw, p.key, time.Now().UTC())
		if err != nil {
			return Config{}, "", err
		}
		return VerifyEnvelopeWithPolicy(raw, p.key, &policy)
	}
	if state, err := readPolicyState02312(filepath.Join(p.store.root, "trust", "trust-state.json")); err != nil || state.Epoch > 0 {
		return Config{}, "", errors.New("Устаревший bootstrap заблокирован после активации делегированного доверия")
	}
	return VerifyEnvelope(raw, p.key)
}
func (p *installer) releaseValid(record activeRecord) bool {
	if !validDigest(record.Digest) || record.Release != record.Digest+"-"+record.Platform || record.Platform != p.target.OS+"-"+p.target.Arch {
		return false
	}
	base := filepath.Join(p.launcherRoot, "releases", record.Release)
	cfgPath := filepath.Join(base, "signed-config.json")
	m, e := os.Lstat(cfgPath)
	if e != nil || !m.Mode().IsRegular() || m.Size() > maxConfigBytes {
		return false
	}
	data, e := os.ReadFile(cfgPath)
	if e != nil || hexDigest(data) != record.ConfigSHA256 {
		return false
	}
	cfg, digest, e := p.verifyConfig(data)
	if e != nil || digest != record.Digest {
		return false
	}
	target, e := cfg.SelectTarget()
	if e != nil {
		return false
	}
	for _, c := range target.Components {
		if !hashFile(filepath.Join(base, ComponentName(c.Name)), c.Artifact) {
			return false
		}
	}
	return true
}
func (p *installer) current() (*activeRecord, error) {
	var result *activeRecord
	for _, slot := range []string{"active-0.json", "active-1.json"} {
		raw, e := os.ReadFile(filepath.Join(p.launcherRoot, slot))
		if e != nil {
			continue
		}
		var r activeRecord
		if e = decodeStrict(raw, &r); e != nil || !p.releaseValid(r) {
			continue
		}
		if result == nil || r.Generation > result.Generation {
			copy := r
			result = &copy
		}
	}
	if result == nil {
		return nil, errors.New("Нет проверенного предыдущего выпуска компонента")
	}
	return result, nil
}
func (p *installer) activate(previous *activeRecord, desired activeRecord) error {
	if !p.releaseValid(desired) {
		return errors.New("Активация непроверенных компонентов запрещена")
	}
	if previous != nil && previous.Digest == desired.Digest && previous.ConfigSHA256 == desired.ConfigSHA256 {
		return nil
	}
	desired.Generation = 1
	if previous != nil {
		desired.Generation = previous.Generation + 1
	}
	if desired.Generation == 0 {
		return errors.New("Переполнение номера поколения")
	}
	before := ""
	if previous != nil {
		before = previous.Release
	}
	if e := atomicSmallWrite(filepath.Join(p.launcherRoot, "switch.journal"), jsonBytes(switchJournal{From: before, To: desired.Release})); e != nil {
		return e
	}
	slot := fmt.Sprintf("active-%d.json", desired.Generation%2)
	if e := atomicSmallWrite(filepath.Join(p.launcherRoot, slot), jsonBytes(desired)); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(p.launcherRoot, "switch.journal"))
	return syncDir(p.launcherRoot)
}

// deactivateFailedFirstRun очищает только активацию поколения 1, созданную текущим запуском. Более поздняя активация или существующий слот восстановления никогда не удаляются. Блокировка процесса инициализации сериализует изменения состояния.
func (p *installer) deactivateFailedFirstRun(active *activeRecord) error {
	if active == nil || active.Generation != 1 {
		return errors.New("Несовпадение поколения первоначальной активации")
	}
	slot := filepath.Join(p.launcherRoot, "active-1.json")
	data, err := os.ReadFile(slot)
	if err != nil {
		return err
	}
	var stored activeRecord
	if err = decodeStrict(data, &stored); err != nil {
		return err
	}
	if stored != *active {
		return errors.New("Состояние первоначальной активации изменилось во время отката")
	}
	if err = os.Remove(slot); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(p.launcherRoot, "switch.journal")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(p.launcherRoot)
}

func (p *installer) prepareAndStart(ctx context.Context, record activeRecord, opts Options) error {
	release := filepath.Join(p.launcherRoot, "releases", record.Release)
	runtimeBin := filepath.Join(release, ComponentName("runtime"))
	desktopBin := filepath.Join(release, ComponentName("desktop"))
	manifestPath, e := p.prepareRecord(ctx, p.config.Manifest, "profile-manifest.json")
	if e != nil {
		return fmt.Errorf("Манифест профиля: %w", e)
	}
	// Используйте существующий проверяющий подписи Runtime ДО чтения настроек Java из профиля или установки игровых данных.
	var gameTrustEnv []string
	if p.configTrustEpoch() > 0 {
		gameTrustEnv = []string{"LAUNCHER_GAME_TRUST_POLICY_FILE=" + filepath.Join(p.store.root, "trust", "active-policy.json")}
	}
	output, e := runChild(ctx, runtimeBin, gameTrustEnv, "verify", "--manifest", manifestPath, "--pinned-public-key", p.config.ProfilePublicKey)
	if e != nil {
		return fmt.Errorf("Проверка подписи профиля: %w (%s)", e, output)
	}
	var profile manifestIdentity
	raw, e := os.ReadFile(manifestPath)
	if e != nil {
		return e
	}
	if e = decodeManifestIdentity(raw, &profile); e != nil {
		return e
	}
	if profile.ProjectID != p.config.ProjectID || profile.ProfileID != p.config.ProfileID || profile.Channel != p.config.Channel {
		return errors.New("Подписанный профиль не соответствует идентификатору bootstrap")
	}
	if opts.LaunchProfile && (!profile.Runtime.Launch.OfflineMode || !validUsername(opts.Username)) {
		return errors.New("Прямой запуск профиля требует подписанного offlineMode и --username (3–16 символов); профили с авторизацией запускаются через Desktop")
	}
	if profile.Runtime.Java.Major == 0 || profile.Runtime.Java.Distribution != "temurin" {
		return errors.New("Неподдерживаемое подписанное требование Managed Java")
	}
	javaManifest, e := p.prepareJavaManifest(ctx, opts)
	if e != nil {
		return e
	}
	env := append(gameTrustEnv, "LAUNCHER_MANAGED_JRE_MANIFEST="+javaManifest, "LAUNCHER_MANAGED_JRE_MANIFEST_SHA256="+p.config.JavaManifest.SHA256)
	if opts.Offline {
		env = append(env, "LAUNCHER_OFFLINE=1")
	}
	if opts.OfflineDir != "" {
		env = append(env, "LAUNCHER_MANAGED_JAVA_OFFLINE_DIR="+filepath.Join(opts.OfflineDir, "managed-jre"))
	}
	major := strconv.FormatUint(uint64(profile.Runtime.Java.Major), 10)
	result, e := runChild(ctx, runtimeBin, env, "java", "ensure", "--major", major, "--distribution", profile.Runtime.Java.Distribution, "--manifest", javaManifest, "--manifest-sha256", p.config.JavaManifest.SHA256)
	if e != nil {
		return fmt.Errorf("Установка Managed Java: %w (%s)", e, result)
	}
	var java javaResult
	if e = json.Unmarshal([]byte(result), &java); e != nil {
		return fmt.Errorf("Результат Managed Java: %w", e)
	}
	if java.Major != profile.Runtime.Java.Major || java.Distribution != "temurin" || java.JavaExecutable == "" {
		return errors.New("Managed Java не вернула проверенную среду выполнения для подписанного профиля")
	}
	// Подписанный локальный манифест уже доступен: повторная загрузка неподписанного манифеста не требуется.
	result, e = runChild(ctx, runtimeBin, env, "sync-local", "--manifest", manifestPath, "--root", p.gameRoot, "--pinned-public-key", p.config.ProfilePublicKey)
	if e != nil {
		return fmt.Errorf("Установка или восстановление профиля: %w (%s)", e, result)
	}
	if !opts.NoDesktop && p.config.BackendURL == "" {
		return errors.New("Для первого запуска Desktop без участия пользователя требуется подписанный backendUrl в bootstrap")
	}
	if !opts.NoDesktop {
		// Установка без интерфейса и прямой запуск CLI не должны изменять или требовать каталог начальной настройки Desktop. Он нужен только для запуска Desktop.
		desktopConfigDir, e := p.ensureDesktopConfig(opts.Username, profile.Runtime.Launch.OfflineMode && opts.Offline)
		if e != nil {
			return e
		}
		env = append(env, "LAUNCHER_CONFIG_DIR="+desktopConfigDir)
		cmd := exec.Command(desktopBin)
		cmd.Env = mergeEnv(env)
		cmd.Dir = release
		if e := cmd.Start(); e != nil {
			return fmt.Errorf("Запуск Desktop: %w", e)
		}
		if e := cmd.Process.Release(); e != nil {
			return e
		}
	}
	if opts.LaunchProfile {
		result, e = runChild(ctx, runtimeBin, env, "launch", "--manifest", manifestPath, "--root", p.gameRoot, "--username", opts.Username, "--pinned-public-key", p.config.ProfilePublicKey)
		if e != nil {
			return fmt.Errorf("Запуск профиля: %w (%s)", e, result)
		}
		var launched struct {
			Success bool `json:"success"`
		}
		if e = json.Unmarshal([]byte(result), &launched); e != nil || !launched.Success {
			return fmt.Errorf("Процесс Minecraft завершился с ошибкой, хотя Runtime CLI сообщил об успешном завершении: %s", result)
		}
	}
	return nil
}

// Сохраните точные байты, подписанные владельцем: никакой повторной сериализации JSON или изменения содержимого. После проверки подписи Prestarter под своей блокировкой выполните атомарную устойчивую замену.
func writeSignedDesktopHandoff0352(path string, raw []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".signed-bootstrap-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// Настройки первого запуска Desktop создаются из уже проверенного подписанного начального содержимого. Никогда не перезаписывайте изменённую пользователем конфигурацию. Desktop получает каталог через существующий параметр переопределения config-dir.
func (p *installer) ensureDesktopConfig(username string, offline bool) (string, error) {
	dir := filepath.Join(p.store.root, "desktop-config")
	if err := safeMkdir(dir); err != nil {
		return "", err
	}
	// Передайте Desktop точные байты, уже проверенные Prestarter. Нативный Desktop независимо проверяет ту же подпись с вшитым корнем доверия и отклоняет неподписанные изменения заданной владельцем привязки.
	if err := writeSignedDesktopHandoff0352(filepath.Join(dir, "bootstrap.signed.json"), p.rawConfig); err != nil {
		return "", err
	}
	if p.configTrustEpoch() > 0 {
		policy, err := os.ReadFile(filepath.Join(p.store.root, "trust", "active-policy.json"))
		if err != nil {
			return "", err
		}
		// Политика уже проверена относительно встроенного корня доверия на более раннем этапе Run.
		if _, _, err := VerifyTrustPolicy(policy, p.key, time.Now().UTC()); err != nil {
			return "", err
		}
		if err := writeSignedDesktopHandoff0352(filepath.Join(dir, "trust-policy.signed.json"), policy); err != nil {
			return "", err
		}
	} else if _, err := os.Lstat(filepath.Join(dir, "trust-policy.signed.json")); err == nil {
		return "", errors.New("Устаревший bootstrap не может заменить делегированную подготовку Desktop")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	path := filepath.Join(dir, "config.json")
	if stat, err := os.Lstat(path); err == nil {
		if !stat.Mode().IsRegular() || stat.Size() > 1024*1024 {
			return "", errors.New("Небезопасная существующая конфигурация Desktop")
		}
		return dir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if username == "" {
		username = "Player"
	}
	config := map[string]any{
		"schemaVersion": "1.0", "backendUrl": p.config.BackendURL,
		"manifestUrl": p.config.Manifest.URL,
		"projectId":   p.config.ProjectID, "profileId": p.config.ProfileID,
		"channel": p.config.Channel, "gameDirectory": p.gameRoot,
		"javaPath": "", "username": username, "memoryMb": 4096,
		"pinnedPublicKey": p.config.ProfilePublicKey,
		"trustPolicyPath": func() string {
			if p.configTrustEpoch() > 0 {
				return filepath.Join(p.store.root, "trust", "active-policy.json")
			}
			return ""
		}(),
		"serverId": p.config.ServerID, "screenWidth": 1280, "screenHeight": 720,
		"fullscreen": false, "autoEnter": p.config.AutoEnter, "serverHost": p.config.ServerHost, "serverPort": func() uint16 {
			if p.config.ServerPort == 0 {
				return 25565
			}
			return p.config.ServerPort
		}(),
		"offlineEnabled": offline, "configPath": "",
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return dir, nil
	}
	if err != nil {
		return "", err
	}
	if _, err = f.Write(encoded); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = syncDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func (p *installer) prepareRecord(ctx context.Context, a Artifact, name string) (string, error) {
	path := filepath.Join(p.store.root, "manifests", a.SHA256+".json")
	source, e := p.store.artifact(ctx, a, name)
	if e != nil {
		return "", e
	}
	if hashFile(path, a) {
		return path, nil
	}
	if e = durableCopy(source, path, a, false); e != nil {
		return "", e
	}
	return path, nil
}
func (p *installer) prepareJavaManifest(ctx context.Context, opts Options) (string, error) {
	if opts.OfflineDir != "" {
		local := filepath.Join(opts.OfflineDir, "managed-jre", "manifest.json")
		if hashFile(local, p.config.JavaManifest) {
			return local, nil
		}
	}
	// Используйте исходный удалённый URL как основу для относительных адресов архивов JRE. Путь Managed Java в Rust самостоятельно проверяет SHA-256 манифеста.
	if !opts.Offline {
		if _, e := p.store.artifact(ctx, p.config.JavaManifest, "java-manifest.json"); e != nil {
			return "", e
		}
		return p.config.JavaManifest.URL, nil
	}
	return "", errors.New("Автономный манифест дистрибутива Java (и архивы) должен находиться в managed-jre/")
}
func decodeManifestIdentity(raw []byte, identity *manifestIdentity) error {
	if len(raw) > 16*1024*1024 {
		return errors.New("Манифест игры превышает допустимый размер")
	}
	return json.Unmarshal(raw, identity)
}

type limitedOutput struct{ bytes.Buffer }

const maxChildOutput = 8 * 1024 * 1024

func (w *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > maxChildOutput-w.Len() {
		return 0, errors.New("Вывод дочернего процесса превысил ограничение")
	}
	return w.Buffer.Write(p)
}
func runChild(ctx context.Context, binary string, additionalEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = mergeEnv(additionalEnv)
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
func mergeEnv(overrides []string) []string {
	keys := map[string]bool{}
	for _, v := range overrides {
		key, _, _ := strings.Cut(v, "=")
		keys[strings.ToUpper(key)] = true
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if !keys[strings.ToUpper(key)] {
			result = append(result, v)
		}
	}
	return append(result, overrides...)
}

// AcquireInstallerLock предоставляет нативную блокировку процесса, уже используемую при инициализации.
func AcquireInstallerLock(path string) (io.Closer, error) { return acquireProcessLock(path) }
