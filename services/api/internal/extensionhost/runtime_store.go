package extensionhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Устойчивые JSON-документы, принадлежащие расширению. Данные хранятся отдельно от
// подписанного пакета, переживают перезапуск хоста и обновление расширения и разделяются по
// расширению и области. Авторизация всегда проверяется брокером; одного токена хоста
// недостаточно для чтения или записи. Не сохраняйте через этот интерфейс секреты.
const runtimeValueLimit0303 = 128 << 10
const runtimeTotalLimit0303 = 4 << 20
const runtimeKeyLimit0303 = 256

var runtimeKeyPattern0303 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func runtimeDir0303(root string, key Key) string {
	h := sha256.Sum256([]byte(key.normalized().String()))
	return filepath.Join(root, "runtime-data", hex.EncodeToString(h[:]))
}

func secureDirectory0303(dir string) error {
	// Отклоняйте символьные ссылки на каждом существующем компоненте пути;
	// вредоносное расширение не должно перенаправить запись брокера через заранее
	// установленную ссылку.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	sep := string(filepath.Separator)
	current := filepath.VolumeName(dir) + sep
	for _, part := range strings.Split(strings.TrimPrefix(dir, current), sep) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if errors.Is(e, os.ErrNotExist) {
			if e = os.Mkdir(current, 0700); e != nil && !errors.Is(e, os.ErrExist) {
				return e
			}
			st, e = os.Lstat(current)
		}
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Родительский путь состояния Runtime не является обычным каталогом: %s", current)
		}
	}
	return nil
}

func runtimeFile0303(dir, kind, key string) (string, error) {
	if !runtimeKeyPattern0303.MatchString(key) {
		return "", errors.New("Недопустимый ключ документа Runtime")
	}
	if kind != "config" && kind != "storage" {
		return "", errors.New("Недопустимый тип документа Runtime")
	}
	hash := sha256.Sum256([]byte(kind + ":" + key))
	return filepath.Join(dir, kind+"-"+hex.EncodeToString(hash[:])+".json"), nil
}

func runtimeWrite0303(ctx context.Context, dir, path string, body json.RawMessage) error {
	if !json.Valid(body) || len(body) > runtimeValueLimit0303 {
		return errors.New("Значение Runtime должно быть JSON размером не более 128 КиБ")
	}
	if err := secureDirectory0303(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	total, count := int64(len(body)), 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("Состояние Runtime содержит специальный файл")
		}
		if filepath.Join(dir, entry.Name()) != path {
			total += info.Size()
			count++
		}
	}
	if total > runtimeTotalLimit0303 || count >= runtimeKeyLimit0303 {
		return errors.New("Превышена квота состояния Runtime")
	}
	name := make([]byte, 16)
	if _, err := rand.Read(name); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(name))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Синхронизация каталога для сохранности при сбое по возможности, если файловая система
	// её поддерживает.
	syncRuntimeDirectory0303(dir)
	return nil
}

// Синхронизация каталогов делает и rename, и unlink устойчивыми на поддерживающих
// ФС. На платформах без fsync каталога сохраняется прежний режим best-effort, а
// не ошибка любой операции с документом.
func syncRuntimeDirectory0303(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func runtimeRead0303(dir, path string) (json.RawMessage, bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > runtimeValueLimit0303 {
		return nil, false, errors.New("Небезопасный файл состояния Runtime")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, runtimeValueLimit0303+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > runtimeValueLimit0303 || !json.Valid(body) {
		return nil, false, errors.New("Состояние Runtime повреждено")
	}
	return body, true, nil
}

func (s *Supervisor) executeRuntime0303(ctx context.Context, st *processState, capName string, req capabilityRequest) capabilityResult0205 {
	parts := strings.Split(capName, ".")
	if len(parts) != 3 || parts[0] != "runtime" || (parts[1] != "config" && parts[1] != "storage") || (parts[2] != "get" && parts[2] != "put" && parts[2] != "delete") {
		return capabilityResult0205{status: 404, err: errors.New("Неизвестная операция Runtime")}
	}
	permission := "storage:read"
	if parts[2] != "get" {
		permission = "storage:write"
	}
	ok, err := s.permissionAllowed0207(ctx, st, permission, "")
	if err != nil {
		return capabilityResult0205{status: 503, err: errors.New("Политика разрешений недоступна")}
	}
	if !ok {
		return capabilityResult0205{status: 403, err: fmt.Errorf("Разрешение %s не предоставлено", permission)}
	}
	dir := runtimeDir0303(s.cfg.ExtensionRoot, st.key)
	path, err := runtimeFile0303(dir, parts[1], req.Key)
	if err != nil {
		return capabilityResult0205{status: 400, err: err}
	}
	s.runtimeMu0303.Lock()
	defer s.runtimeMu0303.Unlock()
	if err := secureDirectory0303(dir); err != nil {
		return capabilityResult0205{status: 500, err: err}
	}
	if parts[2] == "put" {
		if len(req.Value) == 0 {
			return capabilityResult0205{status: 400, err: errors.New("Требуется значение")}
		}
		if err := runtimeWrite0303(ctx, dir, path, req.Value); err != nil {
			return capabilityResult0205{status: 400, err: err}
		}
		return capabilityResult0205{status: 200, value: map[string]any{"saved": true}}
	}
	if parts[2] == "delete" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return capabilityResult0205{status: 500, err: err}
		}
		syncRuntimeDirectory0303(dir)
		return capabilityResult0205{status: 200, value: map[string]any{"deleted": true}}
	}
	body, found, err := runtimeRead0303(dir, path)
	if err != nil {
		return capabilityResult0205{status: 500, err: err}
	}
	if !found {
		return capabilityResult0205{status: 404, err: errors.New("Ключ Runtime не найден")}
	}
	return capabilityResult0205{status: 200, value: map[string]any{"value": body}}
}
