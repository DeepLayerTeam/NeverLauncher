package authupgrade

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture02911(t *testing.T, provider, password string) string {
	t.Helper()
	rows := []scanRow{
		{Kind: "meta", A: "scan-v1"},
		{Kind: "user", A: "user-1", B: "x@example.invalid", C: "Person", D: "player"},
		{Kind: "identity", A: "identity-1", B: "user-1", C: provider, D: "subject-1"},
		{Kind: "profile", A: "user-1", B: "cb872dff-0aa1-4cc4-af5f-2e0f27ca4808", C: "Player_One"},
		{Kind: "provider", A: provider, B: "1"},
		{Kind: "password", A: password, B: "1"},
	}
	var buf bytes.Buffer
	for _, row := range rows {
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.String()
}

func TestPreflightPreventsImplicitCustomProvider02911(t *testing.T) {
	raw := fixture02911(t, "custom-provider", "argon2id")
	if _, err := ScanRows(strings.NewReader(raw), nil); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("custom provider unexpectedly accepted: %v", err)
	}
	cp, err := ScanRows(strings.NewReader(raw), []string{"custom-provider"})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Identity["profile"].Count != 1 || cp.Providers["custom-provider"] != 1 {
		t.Fatalf("unexpected report: %+v", cp)
	}
}

func TestUnknownHashAlwaysBlocks02911(t *testing.T) {
	if _, err := ScanRows(strings.NewReader(fixture02911(t, "local", "unsupported")), nil); err == nil || !strings.Contains(err.Error(), "unknown password hashes") {
		t.Fatalf("unsafe password migration: %v", err)
	}
}

func TestIdentityAndUUIDPreservation02911(t *testing.T) {
	original := fixture02911(t, "local", "fileauth-legacy")
	before, err := ScanRows(strings.NewReader(original), nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := ScanRows(strings.NewReader(original), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(before, after); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(original, "cb872dff-0aa1-4cc4-af5f-2e0f27ca4808", "cb872dff-0aa1-4cc4-af5f-2e0f27ca4809", 1)
	drift, err := ScanRows(strings.NewReader(changed), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(before, drift); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("UUID was silently replaced: %v", err)
	}
	changed = strings.Replace(original, "subject-1", "subject-2", 1)
	drift, err = ScanRows(strings.NewReader(changed), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(before, drift); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("subject was silently replaced: %v", err)
	}
}

func TestCheckpointPersistsNoCredentialsAndCannotOverwrite02911(t *testing.T) {
	cp, err := ScanRows(strings.NewReader(fixture02911(t, "local", "argon2id")), nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth-migration.json")
	if err := Save(path, cp); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cp); err == nil {
		t.Fatal("overwrote safety checkpoint")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte("subject-1")) || bytes.Contains(onDisk, []byte("x@example.invalid")) {
		t.Fatal("raw identifying data leaked into checkpoint")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("checkpoint permissions %v", st.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(cp, loaded); err != nil {
		t.Fatal(err)
	}
}

func TestRejectMissingMarkerAndIncompleteCounts02911(t *testing.T) {
	raw := fixture02911(t, "local", "argon2id")
	if _, err := ScanRows(strings.NewReader(strings.Replace(raw, `"kind":"meta"`, `"kind":"unexpected"`, 1)), nil); err == nil {
		t.Fatal("missing scan marker accepted")
	}
	if _, err := ScanRows(strings.NewReader(strings.Replace(raw, `"b":"1"`, `"b":"2"`, 1)), nil); err == nil {
		t.Fatal("partial scan accepted")
	}
}

func TestSQLReadOnlyAndIssuerGuard02911(t *testing.T) {
	for _, needle := range []string{"REPEATABLE READ READ ONLY", "orphaned auth identities", "orphaned Minecraft profiles", "duplicate Minecraft UUID", "issuer-scoped subject collision", "row_to_json(v)", "password_hash ~"} {
		if !strings.Contains(ReadOnlyScanSQL, needle) {
			t.Errorf("SQL missing %q", needle)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE users", "INSERT INTO"} {
		if strings.Contains(ReadOnlyScanSQL, forbidden) {
			t.Errorf("unsafe mutation %q", forbidden)
		}
	}
}
