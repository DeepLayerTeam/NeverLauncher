package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shadowKeyFixture05012(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(directory, "server-key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("ab", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return directory, keyFile
}

func TestGuardShadow05012RealAppendAndIntegrity(t *testing.T) {
	dir, keyFile := shadowKeyFixture05012(t)
	journal, err := newGuardShadowJournal05012(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.observe("server-1", "session-1", "allowed", "none", 500*time.Microsecond); err != nil {
		t.Fatal(err)
	}
	if err := journal.observe("server-1", "session-1", "revoked", "guard_build_revoked", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := journal.close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "guard-shadow-*.jsonl"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("journals %v: %v", matches, err)
	}
	stat, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm()&0077 != 0 {
		t.Fatal("journal disclosed to other users")
	}
	content, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "session-1") || strings.Contains(string(content), "server-1") {
		t.Fatal("journal leaks raw identities")
	}
	var prev string
	key, _ := hex.DecodeString(strings.Repeat("ab", 32))
	for i, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		signature := record["mac"].(string)
		delete(record, "mac")
		canonical, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		tag := hmac.New(sha256.New, key)
		_, _ = tag.Write(canonical)
		if !hmac.Equal(tag.Sum(nil), mustDecodeHex05012(t, signature)) {
			t.Fatalf("invalid event MAC %d", i)
		}
		if record["prevMac"] != prev || int(record["sequence"].(float64)) != i+1 {
			t.Fatal("broken event chain")
		}
		prev = signature
	}
}

func mustDecodeHex05012(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGuardShadow05012RejectsWeakKeyPermissionsAndBadResults(t *testing.T) {
	dir, keyFile := shadowKeyFixture05012(t)
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := newGuardShadowJournal05012(dir, keyFile); err == nil {
		t.Fatal("accepted public server key")
	}
	if err := os.Chmod(keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := newGuardShadowJournal05012(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err := j.observe("srv", "corr", "unknown", "none", 0); err == nil {
		t.Fatal("accepted invalid outcome")
	}
	if err := j.observe("srv", "corr", "revoked", "token=secret value", 0); err != nil {
		t.Fatal(err)
	}
	if j.seq != 1 {
		t.Fatal("did not write redacted observation")
	}
}
