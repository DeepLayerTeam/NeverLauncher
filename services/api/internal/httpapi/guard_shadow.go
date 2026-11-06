package httpapi

// Теневые свидетельства Guard на сервере создаются только аутентифицированным
// heartbeat ServerBridge после авторитетной проверки сеанса. Журнал наблюдает
// существующее решение контроля доступа, но никогда не выдаёт допуск, не
// подавляет отзыв и не считает heartbeat свежей аттестацией клиента.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var guardShadowReason05012 = regexp.MustCompile(`^[a-z][a-z0-9_:-]{0,95}$`)
var guardShadowVersion05012 = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

type guardShadowJournal05012 struct {
	mu      sync.Mutex
	f       *os.File
	key     []byte
	boot    string
	version string
	prev    string
	seq     uint64
}

func newGuardShadowJournal05012(directory, keyFile, version string) (*guardShadowJournal05012, error) {
	if len(version) > 48 || !guardShadowVersion05012.MatchString(version) {
		return nil, errors.New("Для теневой режим Guard требуется «a valid running product version»")
	}
	if !filepath.IsAbs(directory) || !filepath.IsAbs(keyFile) {
		return nil, errors.New("Guard shadow directory/key: требуется «absolute»")
	}
	di, err := os.Lstat(directory)
	if err != nil || !di.IsDir() || di.Mode()&os.ModeSymlink != 0 || di.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Каталог теневой проверки Guard должен существовать и иметь ограниченные права доступа")
	}
	ki, err := os.Lstat(keyFile)
	if err != nil || !ki.Mode().IsRegular() || ki.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Ключ теневого режима Guard: требуется «a private regular file»")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("Ключ теневого режима Guard: требуется «exactly 32 random bytes in hex»")
	}
	var boot [16]byte
	if _, err = rand.Read(boot[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(boot[:])
	f, err := os.OpenFile(filepath.Join(directory, "guard-shadow-"+id+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &guardShadowJournal05012{f: f, key: key, boot: id, version: version}, nil
}

func (j *guardShadowJournal05012) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}

func guardShadowMAC05012(key []byte, message string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func (j *guardShadowJournal05012) observe(nodeID, correlation, outcome, reason string, elapsed time.Duration) error {
	if correlation == "" || nodeID == "" || (outcome != "allowed" && outcome != "revoked") {
		return errors.New("Некорректное значение: «теневое наблюдение Guard»")
	}
	if !guardShadowReason05012.MatchString(reason) {
		reason = "unspecified"
	}
	if outcome == "allowed" {
		reason = "none"
	}
	if elapsed < 0 {
		elapsed = 0
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return errors.New("Теневой журнал Guard закрыт")
	}
	// Имена, UUID, идентификаторы устройств, адреса и токены никогда не
	// записываются в журнал. Псевдоним сеанса стабилен только для данного секрета,
	// а не глобально.
	record := map[string]any{
		"schema":      "neverlauncher.guard-shadow/v1",
		"version":     j.version,
		"bootId":      j.boot,
		"sequence":    j.seq + 1,
		"prevMac":     j.prev,
		"timestampMs": time.Now().UTC().UnixMilli(),
		"sessionKey":  guardShadowMAC05012(j.key, "guard-session:"+correlation),
		"nodeKey":     guardShadowMAC05012(j.key, "bridge-node:"+nodeID),
		"outcome":     outcome,
		"reason":      reason,
		"durationUs":  elapsed.Microseconds(),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	signature := guardShadowMAC05012(j.key, string(payload))
	record["mac"] = signature
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	n, err := j.f.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return fmt.Errorf("Неполная запись в теневой журнал Guard: %d/%d", n, len(line))
	}
	if err = j.f.Sync(); err != nil {
		return err
	}
	j.seq++
	j.prev = signature
	return nil
}

var guardShadowGlobal05012 struct {
	once    sync.Once
	journal *guardShadowJournal05012
	err     error
}

func recordGuardShadow05012(version, nodeID, correlation, outcome, reason string, elapsed time.Duration) error {
	directory := strings.TrimSpace(os.Getenv("LAUNCHER_GUARD_SHADOW_DIR"))
	keyFile := strings.TrimSpace(os.Getenv("LAUNCHER_GUARD_SHADOW_KEY_FILE"))
	if directory == "" && keyFile == "" {
		return nil
	}
	if directory == "" || keyFile == "" {
		return errors.New("Для теневой режим Guard требуется «both directory and key file»")
	}
	guardShadowGlobal05012.once.Do(func() {
		guardShadowGlobal05012.journal, guardShadowGlobal05012.err = newGuardShadowJournal05012(directory, keyFile, version)
	})
	if guardShadowGlobal05012.err != nil {
		return guardShadowGlobal05012.err
	}
	if guardShadowGlobal05012.journal.version != version {
		return errors.New("Несовпадение: «версия активного журнала теневой проверки Guard»")
	}
	return guardShadowGlobal05012.journal.observe(nodeID, correlation, outcome, reason, elapsed)
}
