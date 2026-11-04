package gravitcredentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFileAuthUnsupportedVerifierNeedsManualReset0444(t *testing.T) {
	src, snapshot := sourceFixture335(t, map[string]string{
		"modules-config/FileAuthSystem/Database.json": `{"11111111-2222-4333-8444-555555555555":{"username":"Player335","password":"` + strings.Repeat("a", 64) + `"}}`,
	})
	got, err := Extract(context.Background(), bytes.NewReader(src), int64(len(src)), snapshot, "")
	if err != nil || len(got) != 1 || got[0].State != "manual_reset" || got[0].PasswordHash != "" {
		t.Fatalf("manual-reset extraction: %+v %v", got, err)
	}
	if got[0].UUID != "11111111-2222-4333-8444-555555555555" {
		t.Fatal("identity was not preserved")
	}
	b, err := json.Marshal(got)
	if err != nil || bytes.Contains(b, []byte(strings.Repeat("a", 64))) {
		t.Fatal("verifier leaked into preview")
	}
	if _, err = Extract(context.Background(), bytes.NewReader(src), int64(len(src)), snapshot, "unsafe-hash"); err == nil {
		t.Fatal("unsupported explicitly requested format accepted")
	}
}

func TestFileAuthMissingVerifierRequiresReset0444(t *testing.T) {
	src, snapshot := sourceFixture335(t, map[string]string{
		"modules-config/FileAuthSystem/Database.json": `{"11111111-2222-4333-8444-555555555555":{"username":"Player335"}}`,
	})
	got, err := Extract(context.Background(), bytes.NewReader(src), int64(len(src)), snapshot, "sha256-hex")
	if err != nil || len(got) != 1 || got[0].State != "manual_reset" || got[0].PasswordHash != "" || !strings.Contains(got[0].Reason, "missing") {
		t.Fatalf("missing verifier: %+v %v", got, err)
	}
}

func TestFileAuthMalformedVerifierRefused0444(t *testing.T) {
	src, snapshot := sourceFixture335(t, map[string]string{
		"modules-config/FileAuthSystem/Database.json": `{"11111111-2222-4333-8444-555555555555":{"username":"Player335","password":"not-a-sha256"}}`,
	})
	if _, err := Extract(context.Background(), bytes.NewReader(src), int64(len(src)), snapshot, "sha256-hex"); err == nil {
		t.Fatal("claimed SHA256 verifier is malformed")
	}
}

func TestFileAuthCanonicalUUIDDuplicateRefused0444(t *testing.T) {
	_, err := parseFileAuthCredentials([]byte(`{"11111111-2222-4333-8444-555555555555":{"password":"a"},"11111111222243338444555555555555":{"password":"b"}}`), "p", "", nil)
	if err == nil {
		t.Fatal("duplicate UUID representations accepted")
	}
}

// Крупные установки Gravit FileAuth не должны отклоняться из-за не связанных с ними
// старых ограничений быстрого импорта 16 МиБ/20 тысяч аккаунтов. Проверяется полный
// путь ZIP → независимо хешированные идентичности MIG04 → проверка учётных данных.
func TestLargeFileAuthBeyondLegacyImporterLimit0444(t *testing.T) {
	if testing.Short() {
		t.Skip("large real-source extraction")
	}
	var data strings.Builder
	data.Grow(19 << 20)
	data.WriteByte('{')
	for i := 0; i < 125000; i++ {
		if i != 0 {
			data.WriteByte(',')
		}
		fmt.Fprintf(&data, `"aaaaaaaa-bbbb-4ccc-8ddd-%012x":{"username":"P%08d","password":"%064x"}`, i+1, i+1, i+1)
	}
	data.WriteByte('}')
	if data.Len() <= 16<<20 || data.Len() > 64<<20 {
		t.Fatalf("incorrect file size for regression test: %d", data.Len())
	}
	src, snapshot := sourceFixture335(t, map[string]string{
		"modules-config/FileAuthSystem/Database.json": data.String(),
	})
	got, err := Extract(context.Background(), bytes.NewReader(src), int64(len(src)), snapshot, "sha256-hex")
	if err != nil || len(got) != 125000 {
		t.Fatalf("large FileAuth source: %d accounts, error %v", len(got), err)
	}
	for _, row := range []Credential{got[0], got[len(got)-1]} {
		if row.State != "importable" || row.PasswordHash == "" {
			t.Fatal("large fileauth dropped a valid verifier")
		}
	}
}
