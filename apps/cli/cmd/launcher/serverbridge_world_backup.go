package main

// Резервные копии игровых миров намеренно независимы от резервных копий Backend/PostgreSQL.
// Единственная поддерживаемая политика согласованности живого сервера — подтверждённая
// корректная остановка через Host Supervisor, который передаёт Minecraft команду `stop`.
// Файлы копируются только после остановки игры; неподтверждённый save-all никогда не
// считается согласованным онлайн-снимком.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const worldBackupSchema02810 = "launcher-world-backup/v1"

var worldBackupID02810 = regexp.MustCompile(`^[0-9a-f]{32}$`)

type worldBackupEntry02810 struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type worldBackupManifest02810 struct {
	Schema      string                  `json:"schema"`
	ID          string                  `json:"id"`
	CreatedAt   string                  `json:"createdAt"`
	Consistency string                  `json:"consistency"`
	Platform    string                  `json:"platform,omitempty"`
	Worlds      []string                `json:"worlds"`
	TotalBytes  int64                   `json:"totalBytes"`
	Entries     []worldBackupEntry02810 `json:"entries"`
}
type worldBackupLock02810 struct {
	PID      int    `json:"pid"`
	Identity string `json:"identity"`
	Nonce    string `json:"nonce"`
}

func worldBackupHandle02810(args []string) error {
	if len(args) == 0 {
		return errors.New("Использование: nl server-bridge host world-backup create|verify|restore|release|list [--server-root PATH] [--backup-root PATH]")
	}
	action := args[0]
	args = args[1:]
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	dir, err := worldBackupLocation02810(root, flagValue(args, "--backup-root", ""))
	if err != nil {
		return err
	}
	if holdID := flagValue(args, "--hold-id", ""); holdID != "" && !worldCohortID0518.MatchString(holdID) {
		return errors.New("Некорректное значение: идентификатор удержания группы резервных копий миров")
	}
	if action == "list" {
		return worldBackupList02810(dir, flagValue(args, "--output", ""))
	}
	if action == "gate-recover" {
		if flagValue(args, "--confirm", "") != "stale-gate" {
			return errors.New("gate-recover: требуется «--confirm stale-gate; reconcile Host Supervisor/JVM first»")
		}
		return worldBackupHostGateRecover04110(root)
	}
	if action == "release" {
		holdID := flagValue(args, "--hold-id", "")
		return worldBackupReleaseCohortHold0518(root, holdID)
	}
	if action != "create" && action != "verify" && action != "restore" {
		return fmt.Errorf("Неизвестное значение: «операция резервного копирования мира» %q", action)
	}
	if err = worldBackupPrivateDir02810(dir); err != nil {
		return err
	}
	release, err := worldBackupLockAcquire02810(dir)
	if err != nil {
		return err
	}
	defer release()
	var m worldBackupManifest02810
	switch action {
	case "create":
		policy := strings.TrimSpace(flagValue(args, "--consistency", "stopped"))
		if policy != "stopped" && policy != "stop" {
			return errors.New("Параметр --consistency должен иметь значение stopped или stop")
		}
		worlds := multiFlagValues01910(args, "--world")
		// Проверяйте выбор до остановки действующего сервера.
		candidates, checkErr := worldBackupWorlds02810(root, worlds)
		if checkErr != nil {
			return checkErr
		}
		if _, checkErr = worldBackupSources02810(root, candidates); checkErr != nil {
			return checkErr
		}
		// Сериализуйте ВЕСЬ интервал остановки записи и копирования относительно любого
		// запуска JVM, включая перезапуски после сбоев, через атомарный барьер хоста.
		// Барьер захватывается до чтения состояния хоста, чтобы новый супервизор не успел
		// войти после проверки остановки.
		releaseGate, gateErr := worldBackupHostGateAcquire04110(root, "backup")
		if gateErr != nil {
			return gateErr
		}
		keepGate := false
		defer func() {
			if !keepGate {
				releaseGate()
			}
		}()
		if err = worldBackupQuiesce02810(root, policy); err != nil {
			return err
		}
		m, err = worldBackupCreate02810(root, dir, worlds, policy)
		if err == nil {
			if holdID := flagValue(args, "--hold-id", ""); holdID != "" {
				// Никогда не освобождайте каталог после неудачной частичной записи удержания.
				keepGate = true
				err = worldBackupPersistCohortHold0518(root, holdID, m.ID)
			}
		}
	case "verify", "restore":
		id := flagValue(args, "--id", "")
		if !worldBackupID02810.MatchString(id) {
			return errors.New("Параметр --id должен содержать 32-символьный шестнадцатеричный идентификатор резервной копии")
		}
		m, err = worldBackupVerify02810(filepath.Join(dir, id))
		if err != nil {
			return err
		}
		if action == "restore" {
			dest := flagValue(args, "--destination", "")
			if dest == "" {
				return errors.New("Для восстановление требуется «--destination (new, non-existing directory)»")
			}
			if flagValue(args, "--confirm", "") != id {
				return errors.New("Для восстановление требуется «--confirm matching the backup ID»")
			}
			if err = worldBackupRestore02810(root, dir, m, filepath.Join(dir, id), dest); err != nil {
				return err
			}
		}
	}
	if err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schema": worldBackupSchema02810, "action": action, "backupRoot": dir, "manifest": m})
}

func worldBackupLocation02810(root, requested string) (string, error) {
	if requested == "" {
		hash := sha256.Sum256([]byte(root))
		requested = filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+"-world-backups-"+hex.EncodeToString(hash[:4]))
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if err = worldBackupDisjoint02810(root, abs); err != nil {
		return "", err
	}
	// Запретите переходы по символьным ссылкам на всём пути хранения резервных копий, включая родительские каталоги.
	if err = worldBackupNoSymlinkAncestors02810(abs); err != nil {
		return "", err
	}
	return abs, nil
}
func worldBackupDisjoint02810(a, b string) error {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return errors.New("пути резервных копий игрового мира: запрещено пересекаться с корнем сервера, хранилищем копий или каталогом восстановления")
		}
	}
	return nil
}
func worldBackupNoSymlinkAncestors02810(path string) error {
	path = filepath.Clean(path)
	for {
		fi, err := os.Lstat(path)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("Символьная ссылка в пути: %s", path)
			}
			if !fi.IsDir() {
				return fmt.Errorf("Указанный путь не является каталогом: %s", path)
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
func worldBackupPrivateDir02810(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("Каталог резервного копирования игрового мира: требуется закрытый каталог с правами 0700, не являющийся символической ссылкой")
	}
	return nil
}
func worldBackupRandom02810() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func worldBackupLockAcquire02810(dir string) (func(), error) {
	identity := hostOwnIdentity0282()
	if identity == "" {
		return nil, errors.New("Для резервного копирования необходим проверяемый идентификатор процесса хоста")
	}
	nonce, err := worldBackupRandom02810()
	if err != nil {
		return nil, err
	}
	own := worldBackupLock02810{PID: os.Getpid(), Identity: identity, Nonce: nonce}
	path := filepath.Join(dir, "operation.lock")
	data, _ := json.Marshal(own)
	for tries := 0; tries < 3; tries++ {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			_, e = f.Write(data)
			if e == nil {
				e = f.Sync()
			}
			ce := f.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				_ = os.Remove(path)
				return nil, e
			}
			return func() {
				var cur worldBackupLock02810
				if worldBackupReadJSON02810(path, &cur) == nil && cur == own {
					_ = os.Remove(path)
				}
			}, nil
		}
		if !errors.Is(e, os.ErrExist) {
			return nil, e
		}
		fi, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !fi.Mode().IsRegular() {
			return nil, errors.New("блокировка резервного копирования игрового мира: требуется обычный файл")
		}
		var existing worldBackupLock02810
		if err := worldBackupReadJSON02810(path, &existing); err != nil {
			return nil, err
		}
		if existing.Identity == "" || hostIdentityMatches0282(existing.PID, existing.Identity) {
			return nil, errors.New("Резервное копирование мира уже выполняется или владелец блокировки не подтверждён")
		}
		stale := path + ".stale-" + nonce
		if err := os.Rename(path, stale); err != nil {
			return nil, err
		}
		_ = os.Remove(stale)
	}
	return nil, errors.New("Конфликт блокировки резервного копирования мира")
}
func worldBackupReadJSON02810(path string, v any) error {
	check, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !check.Mode().IsRegular() {
		return errors.New("Метаданные резервной копии: требуется существующий обычный файл")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err == nil && !os.SameFile(check, fi) {
		return errors.New("Метаданные резервной копии изменились во время открытия")
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 32<<20 {
		return errors.New("Некорректное значение: метаданные резервной копии файл")
	}
	dec := json.NewDecoder(io.LimitReader(f, 32<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("Обнаружены лишние данные после: метаданные резервной копии")
	}
	return nil
}
func worldBackupQuiesce02810(root, policy string) error {
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if errors.Is(err, os.ErrNotExist) {
		// Отсутствие runtime.json не доказывает простоя хоста: супервизор может
		// держать блокировку, готовя первый дочерний процесс.
		lock, lockErr := readServerBridgeHostLock01910(paths["lock"])
		if lockErr == nil {
			if lock.Identity == "" || hostIdentityMatches0282(lock.PID, lock.Identity) || updaterProcessAlive0156(lock.PID) {
				return errors.New("Блокировка супервизора Host существует без Runtime: резервное копирование небезопасно")
			}
		} else if !errors.Is(lockErr, os.ErrNotExist) {
			return fmt.Errorf("Не удалось проверить «блокировка Host Supervisor:» %w", lockErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("Не удалось определить состояние хоста: %w", err)
	}
	if state.ProcessPID > 0 {
		if !hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
			return errors.New("PID Minecraft не подтверждён или устарел; проверьте состояние перед копированием мира")
		}
		if policy != "stop" {
			return errors.New("Minecraft работает: укажите --consistency stop для контролируемой корректной остановки")
		}
		stopResult := filepath.Join(paths["dir"], "world-backup-stop-result.json")
		defer os.Remove(stopResult)
		if err = stopServerBridgeHost01910([]string{"--server-root", root, "--output", stopResult}); err != nil {
			return err
		}
	}
	// Супервизор может ещё завершаться после сообщения об остановке. Дождитесь исчезновения
	// точной прежней идентичности; не допускайте гонки с перезапуском.
	deadline := time.Now().Add(5 * time.Second)
	var current serverBridgeHostRuntime01910
	for {
		current, err = readServerBridgeHostRuntime01910(paths["runtime"])
		if err != nil {
			return err
		}
		if !hostIdentityMatches0282(current.SupervisorPID, current.SupervisorIdentity) || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if current.ProcessPID > 0 || hostIdentityMatches0282(current.ProcessPID, current.ProcessIdentity) {
		return errors.New("Остановка процесса Minecraft не подтверждена")
	}
	if current.Status == "starting" || current.Status == "running" || current.Status == "restarting" {
		return fmt.Errorf("Небезопасное значение: состояние среды выполнения хоста %s", current.Status)
	}
	if hostIdentityMatches0282(current.SupervisorPID, current.SupervisorIdentity) {
		return errors.New("Контроллер процессов всё ещё запущен: нельзя гарантировать отсутствие перезапуска во время резервного копирования")
	}
	if current.Status == "crashed" || current.Status == "failed" || current.Status == "restarting" {
		return errors.New("Мир после сбоя не подтверждён как согласованный источник резервной копии")
	}
	if current.StopMethod == "kill" || current.StopMethod == "terminate" {
		return errors.New("Последнее завершение Minecraft было принудительным; сохранение мира на диск не подтверждено")
	}
	if current.Status == "stopped" && (current.StopMethod != "console-stop" || current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("Последняя остановка Minecraft не подтверждена как корректная")
	}
	if current.Status == "exited" && (current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("Последний выход Minecraft был аварийным")
	}
	if policy == "stop" && state.ProcessPID > 0 && (current.StopMethod != "console-stop" || current.ExitCode == nil || *current.ExitCode != 0) {
		return errors.New("Корректная остановка Minecraft не подтверждена; резервное копирование мира запрещено")
	}
	if lock, err := readServerBridgeHostLock01910(paths["lock"]); err == nil && (hostIdentityMatches0282(lock.PID, lock.Identity) || (lock.Identity == "" && updaterProcessAlive0156(lock.PID))) {
		return errors.New("Блокировка работающего супервизора Host препятствует согласованному резервному копированию")
	}
	return nil
}
func worldBackupValidRelative02810(name string) bool {
	if name == "" || strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') || strings.Contains(name, ":") || filepath.IsAbs(name) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/")
}
func worldBackupWorlds02810(root string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		level := "world"
		b, err := os.ReadFile(filepath.Join(root, "server.properties"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "level-name=") {
					level = strings.TrimSpace(strings.TrimPrefix(line, "level-name="))
					break
				}
			}
		}
		requested = []string{level}
		for _, name := range []string{level + "_nether", level + "_the_end"} {
			if fi, err := os.Lstat(filepath.Join(root, name)); err == nil && fi.IsDir() {
				requested = append(requested, name)
			}
		}
	}
	selected := map[string]bool{}
	worlds := []string{}
	for _, name := range requested {
		if !worldBackupValidRelative02810(name) || strings.Contains(name, "/") || name == ".launcher" {
			return nil, fmt.Errorf("Некорректное значение: каталог мира %q", name)
		}
		if selected[name] {
			continue
		}
		selected[name] = true
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			return nil, fmt.Errorf("игровой мир %s: %w", name, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("Для игрового мира %s необходим существующий каталог", name)
		}
		worlds = append(worlds, name)
	}
	sort.Strings(worlds)
	return worlds, nil
}
func worldBackupSources02810(root string, worlds []string) ([]string, error) {
	sources := append([]string{}, worlds...)
	for _, name := range []string{"plugins", "config", "server.properties", "bukkit.yml", "spigot.yml", "paper.yml", "purpur.yml", "permissions.yml", "ops.json", "whitelist.json", "banned-players.json", "banned-ips.json", "velocity.toml", "waterfall.yml", "bungee.yml"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			sources = append(sources, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// Запрещайте перекрывающиеся записи, иначе один файл можно будет сохранить дважды.
	seen := map[string]bool{}
	for _, s := range sources {
		if seen[s] {
			return nil, fmt.Errorf("Мир %q пересекается с каталогом конфигурации", s)
		}
		seen[s] = true
	}
	sort.Strings(sources)
	return sources, nil
}
func worldBackupCollect02810(root string, sources []string) ([]worldBackupEntry02810, error) {
	entries := []worldBackupEntry02810{}
	for _, name := range sources {
		err := filepath.WalkDir(filepath.Join(root, name), func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !worldBackupValidRelative02810(rel) {
				return fmt.Errorf("Некорректное значение: относительный путь к источнику %s", rel)
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			ent := worldBackupEntry02810{Path: rel, Mode: uint32(info.Mode().Perm())}
			if info.IsDir() {
				ent.Type = "dir"
			} else if info.Mode().IsRegular() {
				ent.Type = "file"
				ent.Size = info.Size()
			} else {
				return fmt.Errorf("Небезопасное значение: запись резервной копии игрового мира: %s (символическая ссылка или специальный файл)", rel)
			}
			entries = append(entries, ent)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if len(entries) == 0 {
		return nil, errors.New("Пустое значение: выбор резервной копии")
	}
	return entries, nil
}
func worldBackupCopy02810(src, dst string, expectedSize int64, mode fs.FileMode) (string, error) {
	info, err := os.Lstat(src)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		return "", fmt.Errorf("Обнаружено изменение: источник: %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	openInfo, err := in.Stat()
	if err != nil || !os.SameFile(info, openInfo) {
		return "", errors.New("Исходный файл изменился при открытии")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, hasher), in)
	if copyErr == nil && n != expectedSize {
		copyErr = errors.New("Размер исходного файла изменился при копировании")
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	after, statErr := in.Stat()
	if copyErr == nil && (statErr != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime())) {
		copyErr = errors.New("Исходный файл изменился во время резервного копирования")
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return "", copyErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
func worldBackupWriteManifest02810(path string, m worldBackupManifest02810) error {
	// Манифест служит маркером фиксации; до его записи содержимое считается неполным.
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	c := f.Close()
	if err != nil {
		return err
	}
	return c
}
func worldBackupSyncDir02810(dir string) error {
	// Windows не поддерживает синхронизацию дескрипторов каталогов через os.File.Sync; отдельные
	// файлы данных и манифест сбрасываются на диск до переименования.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func worldBackupCreate02810(root, dir string, requested []string, policy string) (worldBackupManifest02810, error) {
	var empty worldBackupManifest02810
	worlds, err := worldBackupWorlds02810(root, requested)
	if err != nil {
		return empty, err
	}
	sources, err := worldBackupSources02810(root, worlds)
	if err != nil {
		return empty, err
	}
	entries, err := worldBackupCollect02810(root, sources)
	if err != nil {
		return empty, err
	}
	id, err := worldBackupRandom02810()
	if err != nil {
		return empty, err
	}
	stage := filepath.Join(dir, ".partial-"+id)
	if err = os.Mkdir(stage, 0700); err != nil {
		return empty, err
	}
	defer os.RemoveAll(stage)
	payload := filepath.Join(stage, "payload")
	if err = os.Mkdir(payload, 0700); err != nil {
		return empty, err
	}
	platform := "unknown"
	if cfg, readErr := readServerBridgeHostConfig01910(hostPaths01910(root)["config"]); readErr == nil {
		platform = cfg.Platform
	}
	m := worldBackupManifest02810{Schema: worldBackupSchema02810, ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Consistency: "confirmed-stopped", Platform: platform, Worlds: worlds, Entries: entries}
	for i := range m.Entries {
		ent := &m.Entries[i]
		dst := filepath.Join(payload, filepath.FromSlash(ent.Path))
		if ent.Type == "dir" {
			if err = os.Mkdir(dst, 0700); err != nil {
				return empty, err
			}
			continue
		}
		digest, copyErr := worldBackupCopy02810(filepath.Join(root, filepath.FromSlash(ent.Path)), dst, ent.Size, 0600)
		if copyErr != nil {
			return empty, copyErr
		}
		ent.SHA256 = digest
		m.TotalBytes += ent.Size
	}
	// До публикации манифеста докажите полноту сохранённого содержимого.
	if err = worldBackupWriteManifest02810(filepath.Join(stage, "manifest.json"), m); err != nil {
		return empty, err
	}
	if _, err = worldBackupVerify02810(stage); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(payload); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(stage); err != nil {
		return empty, err
	}
	if err = os.Rename(stage, filepath.Join(dir, id)); err != nil {
		return empty, err
	}
	if err = worldBackupSyncDir02810(dir); err != nil {
		return m, fmt.Errorf("Резервная копия опубликована, но синхронизация каталога не удалась; проверьте ID %s: %w", id, err)
	}
	return m, nil
}
func worldBackupManifestValid02810(m worldBackupManifest02810) error {
	if m.Schema != worldBackupSchema02810 || !worldBackupID02810.MatchString(m.ID) || m.Consistency != "confirmed-stopped" || len(m.Worlds) == 0 || len(m.Entries) == 0 || len(m.Entries) > 1000000 {
		return errors.New("Некорректное значение: мир манифест резервной копии")
	}
	found := map[string]string{}
	worlds := map[string]bool{}
	var total int64
	for _, w := range m.Worlds {
		if !worldBackupValidRelative02810(w) || strings.Contains(w, "/") || worlds[w] {
			return errors.New("Некорректное значение: выбор игрового мира")
		}
		worlds[w] = true
	}
	for _, e := range m.Entries {
		if !worldBackupValidRelative02810(e.Path) || found[e.Path] != "" || e.Mode > 0777 {
			return fmt.Errorf("Некорректная или повторяющаяся запись манифеста: %q", e.Path)
		}
		if e.Type != "dir" && e.Type != "file" {
			return errors.New("Некорректное значение: тип записи резервной копии")
		}
		if e.Type == "dir" && (e.Size != 0 || e.SHA256 != "") {
			return errors.New("Некорректное значение: метаданные каталога")
		}
		if e.Type == "file" && (e.Size < 0 || len(e.SHA256) != 64) {
			return errors.New("Некорректное значение: метаданные файла")
		}
		if e.Type == "file" {
			if _, err := hex.DecodeString(e.SHA256); err != nil {
				return err
			}
			if total > int64(^uint64(0)>>1)-e.Size {
				return errors.New("Переполнение размера резервной копии")
			}
			total += e.Size
		}
		parent := e.Path
		for strings.Contains(parent, "/") {
			parent = parent[:strings.LastIndex(parent, "/")]
			if found[parent] == "file" {
				return errors.New("Путь манифеста проходит через обычный файл")
			}
		}
		found[e.Path] = e.Type
	}
	if total != m.TotalBytes {
		return errors.New("Несовпадение: размер манифеста в байтах")
	}
	for w := range worlds {
		if found[w] != "dir" {
			return fmt.Errorf("Отсутствует: каталог мира %s", w)
		}
	}
	for path := range found {
		if strings.Contains(path, "/") {
			parent := path[:strings.LastIndex(path, "/")]
			if found[parent] != "dir" {
				return errors.New("В манифесте отсутствует родительский каталог")
			}
		}
	}
	return nil
}
func worldBackupVerify02810(dir string) (worldBackupManifest02810, error) {
	var m worldBackupManifest02810
	fi, err := os.Lstat(dir)
	if err != nil {
		return m, err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return m, errors.New("Элемент резервной копии не является настоящим каталогом")
	}
	payloadInfo, err := os.Lstat(filepath.Join(dir, "payload"))
	if err != nil {
		return m, err
	}
	if !payloadInfo.IsDir() || payloadInfo.Mode()&os.ModeSymlink != 0 {
		return m, errors.New("Каталог данных резервной копии не является настоящим каталогом")
	}
	if err := worldBackupReadJSON02810(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return m, err
	}
	if err := worldBackupManifestValid02810(m); err != nil {
		return m, err
	}
	expected := map[string]worldBackupEntry02810{}
	for _, e := range m.Entries {
		expected[e.Path] = e
	}
	payload := filepath.Join(dir, "payload")
	count := 0
	err = filepath.WalkDir(payload, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == payload {
			return nil
		}
		rel, err := filepath.Rel(payload, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		e, ok := expected[rel]
		if !ok {
			return fmt.Errorf("Неожиданное значение: элемент данных резервной копии %s", rel)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if e.Type == "dir" {
			if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("Некорректное значение: каталог резервной копии %s", rel)
			}
		} else {
			if !fi.Mode().IsRegular() || fi.Size() != e.Size {
				return fmt.Errorf("Некорректный размер или тип файла %s", rel)
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, err := io.Copy(h, f)
			_ = f.Close()
			if err != nil {
				return err
			}
			if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
				return fmt.Errorf("Несовпадение контрольной суммы %s", rel)
			}
		}
		count++
		return nil
	})
	if err != nil {
		return m, err
	}
	if count != len(expected) {
		return m, errors.New("Отсутствует: элементы данных резервной копии")
	}
	return m, nil
}
func worldBackupRestore02810(root, store string, m worldBackupManifest02810, source, dest string) error {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	if err = worldBackupDisjoint02810(root, abs); err != nil {
		return err
	}
	if err = worldBackupDisjoint02810(store, abs); err != nil {
		return err
	}
	if err = worldBackupNoSymlinkAncestors02810(filepath.Dir(abs)); err != nil {
		return err
	}
	if _, err = os.Lstat(abs); err == nil {
		return errors.New("Каталог восстановления уже существует: перезапись запрещена")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(abs)
	if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
		return errors.New("Родительский каталог назначения восстановления должен существовать и быть настоящим каталогом")
	}
	stage := filepath.Join(parent, "."+filepath.Base(abs)+".restore-"+m.ID)
	if err = os.Mkdir(stage, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, e := range m.Entries {
		to := filepath.Join(stage, filepath.FromSlash(e.Path))
		from := filepath.Join(source, "payload", filepath.FromSlash(e.Path))
		if e.Type == "dir" {
			if err = os.Mkdir(to, 0700); err != nil {
				return err
			}
			continue
		}
		digest, copyErr := worldBackupCopy02810(from, to, e.Size, 0600)
		if copyErr != nil {
			return copyErr
		}
		if digest != e.SHA256 {
			return fmt.Errorf("Контрольная сумма восстановленного файла не совпадает: %s", e.Path)
		}
		if err = os.Chmod(to, os.FileMode(e.Mode)&0777); err != nil {
			return err
		}
	}
	// После заполнения файлов применяйте права каталогов снизу вверх.
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		if e.Type == "dir" {
			if err = os.Chmod(filepath.Join(stage, filepath.FromSlash(e.Path)), os.FileMode(e.Mode)&0777); err != nil {
				return err
			}
		}
	}
	// Восстановленное содержимое независимо проверяется до атомарной публикации.
	for _, e := range m.Entries {
		if e.Type != "file" {
			continue
		}
		f, openErr := os.Open(filepath.Join(stage, filepath.FromSlash(e.Path)))
		if openErr != nil {
			return openErr
		}
		h := sha256.New()
		_, readErr := io.Copy(h, f)
		_ = f.Close()
		if readErr != nil {
			return readErr
		}
		if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
			return errors.New("Восстановленные данные не прошли проверку")
		}
	}
	if err = worldBackupSyncDir02810(stage); err != nil {
		return err
	}
	if err = os.Rename(stage, abs); err != nil {
		return err
	}
	return worldBackupSyncDir02810(parent)
}
func worldBackupList02810(dir, output string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return writeOrPrintJSON(output, map[string]any{"schema": worldBackupSchema02810, "backups": []any{}})
	}
	if err != nil {
		return err
	}
	backups := []worldBackupManifest02810{}
	for _, e := range entries {
		if !e.IsDir() || !worldBackupID02810.MatchString(e.Name()) {
			continue
		}
		var m worldBackupManifest02810
		if worldBackupReadJSON02810(filepath.Join(dir, e.Name(), "manifest.json"), &m) == nil && m.ID == e.Name() && worldBackupManifestValid02810(m) == nil {
			backups = append(backups, m)
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt > backups[j].CreatedAt })
	return writeOrPrintJSON(output, map[string]any{"schema": worldBackupSchema02810, "backupRoot": dir, "backups": backups})
}
