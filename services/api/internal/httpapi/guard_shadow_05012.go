package httpapi

// Server-side Guard shadow evidence: produced only by an authenticated
// ServerBridge heartbeat after the authoritative session check. This journal
// observes the existing enforcement decision; it never grants admission,
// suppresses a revocation or treats a heartbeat as fresh client attestation.

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

type guardShadowJournal05012 struct {
	mu   sync.Mutex
	f    *os.File
	key  []byte
	boot string
	prev string
	seq  uint64
}

func newGuardShadowJournal05012(directory, keyFile string) (*guardShadowJournal05012, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(keyFile) {
		return nil, errors.New("Guard shadow directory/key must be absolute")
	}
	di, err := os.Lstat(directory)
	if err != nil || !di.IsDir() || di.Mode()&os.ModeSymlink != 0 || di.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Guard shadow directory must exist with private permissions")
	}
	ki, err := os.Lstat(keyFile)
	if err != nil || !ki.Mode().IsRegular() || ki.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Guard shadow key must be a private regular file")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("Guard shadow key must be exactly 32 random bytes in hex")
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
	return &guardShadowJournal05012{f: f, key: key, boot: id}, nil
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
		return errors.New("invalid Guard shadow observation")
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
		return errors.New("Guard shadow journal closed")
	}
	// Names, UUIDs, device identifiers, addresses and tokens are never logged.
	// The session pseudonym is stable only for this secret, not globally.
	record := map[string]any{
		"schema":      "neverlauncher.guard-shadow/v1",
		"version":     "0.50.12",
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
		return fmt.Errorf("short Guard shadow journal write %d/%d", n, len(line))
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

func recordGuardShadow05012(nodeID, correlation, outcome, reason string, elapsed time.Duration) error {
	directory := strings.TrimSpace(os.Getenv("LAUNCHER_GUARD_SHADOW_DIR"))
	keyFile := strings.TrimSpace(os.Getenv("LAUNCHER_GUARD_SHADOW_KEY_FILE"))
	if directory == "" && keyFile == "" {
		return nil
	}
	if directory == "" || keyFile == "" {
		return errors.New("Guard shadow requires both directory and key file")
	}
	guardShadowGlobal05012.once.Do(func() {
		guardShadowGlobal05012.journal, guardShadowGlobal05012.err = newGuardShadowJournal05012(directory, keyFile)
	})
	if guardShadowGlobal05012.err != nil {
		return guardShadowGlobal05012.err
	}
	return guardShadowGlobal05012.journal.observe(nodeID, correlation, outcome, reason, elapsed)
}
