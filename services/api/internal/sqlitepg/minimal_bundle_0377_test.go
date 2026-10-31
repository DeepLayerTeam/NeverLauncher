package sqlitepg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestMinimalBundle077Validation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, _, err := verifyMinimalBundle0377(ctx, dir); err == nil {
		t.Fatal("empty backup accepted")
	}
	if _, err := ImportMinimalBundle0377(ctx, dir, ""); err == nil {
		t.Fatal("empty DSN accepted")
	}
	if _, err := ExportMinimalBundle0377(ctx, "", filepath.Join(dir, "other")); err == nil {
		t.Fatal("empty DSN accepted")
	}
}

func fixtureMinimalBundle0377(t *testing.T, base string) string {
	t.Helper()
	root := filepath.Join(base, "source-bundle")
	payload := filepath.Join(root, "payload")
	for _, d := range []string{root, payload, filepath.Join(payload, "config"), filepath.Join(payload, "db"), filepath.Join(payload, "storage")} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"db/http.sqlite", "db/coordinator.sqlite"} {
		p := filepath.Join(payload, name)
		db, err := sql.Open("sqlite", p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`CREATE TABLE test_records (id INTEGER PRIMARY KEY, value BLOB NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO test_records(id,value) VALUES(1,?)`, []byte{0, 2, 255, 128}); err != nil {
			t.Fatal(err)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(p, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Store a real-world-shaped env and arbitrary binary file, not only SQLite.
	for name, data := range map[string][]byte{"config/backend.env": []byte("NEVERLAUNCHER_REPOSITORY_DRIVER=sqlite\nNEVERLAUNCHER_DEPLOYMENT_MODE=single-node\n"), "storage/client.bin": {0, 1, 2, 3, 255, 0, 11}} {
		if err := os.WriteFile(filepath.Join(payload, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := MinimalBundleManifest0377{Format: minimalBundleFormat0377, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRoot: "/var/lib/launcher", Directories: []string{".", "config", "db", "storage"}}
	for _, p := range []string{"config/backend.env", "db/coordinator.sqlite", "db/http.sqlite", "storage/client.bin"} {
		n, sum, err := digestFile0377(filepath.Join(payload, p))
		if err != nil {
			t.Fatal(err)
		}
		kind := "file"
		if p == "db/http.sqlite" || p == "db/coordinator.sqlite" {
			kind = "sqlite"
		}
		m.Files = append(m.Files, MinimalBundleFile0377{Path: p, Kind: kind, Bytes: n, SHA256: sum, Mode: 0600})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestMinimalBundlePostgreSQLRoundTrip0377(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL service required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err = pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, MinimalBundleSchema0377).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	pg.Close(ctx)
	if exists {
		t.Fatal("migration test requires empty isolated target schema")
	}
	t.Cleanup(func() {
		p, e := pgx.Connect(context.Background(), dsn)
		if e == nil {
			_, _ = p.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+quoted(MinimalBundleSchema0377)+" CASCADE")
			_ = p.Close(context.Background())
		}
	})
	base := t.TempDir()
	input := fixtureMinimalBundle0377(t, base)
	importResult, err := ImportMinimalBundle0377(ctx, input, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if importResult.ReadyForBackendCutover || importResult.Files != 4 || importResult.Bytes <= 0 {
		t.Fatalf("unsafe transfer result %+v", importResult)
	}
	if _, err = ImportMinimalBundle0377(ctx, input, dsn); err == nil {
		t.Fatal("import overwrote immutable transfer")
	}
	restored := filepath.Join(base, "restored-bundle")
	exportResult, err := ExportMinimalBundle0377(ctx, dsn, restored)
	if err != nil {
		t.Fatal(err)
	}
	if exportResult != importResult {
		t.Fatalf("manifest/bytes changed between imports: %+v %+v", importResult, exportResult)
	}
	if _, _, err = verifyMinimalBundle0377(ctx, restored); err != nil {
		t.Fatalf("reverse transfer corrupt: %v", err)
	}
	for _, name := range []string{"manifest.json", "payload/config/backend.env", "payload/db/http.sqlite", "payload/db/coordinator.sqlite", "payload/storage/client.bin"} {
		a, err := os.ReadFile(filepath.Join(input, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(restored, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("roundtrip changed %s", name)
		}
	}
	if _, err = ExportMinimalBundle0377(ctx, dsn, restored); err == nil {
		t.Fatal("existing destination overwritten")
	}
	pg, err = pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close(ctx)
	if _, err = pg.Exec(ctx, "TRUNCATE "+minimalRef0377("chunks")); err == nil {
		t.Fatal("immutable project files could be truncated")
	}
	if _, err = pg.Exec(ctx, "UPDATE "+minimalRef0377("files")+" SET bytes=0"); err == nil {
		t.Fatal("immutable project manifest could be changed")
	}
	// Source tampering must be rejected without modifying the committed copy.
	f := filepath.Join(input, "payload/storage/client.bin")
	if err = os.WriteFile(f, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ImportMinimalBundle0377(ctx, input, dsn); err == nil {
		t.Fatal("tampered source accepted")
	}
}

func TestMinimalDigests0377(t *testing.T) {
	h := sha256.Sum256([]byte("abc"))
	if len(hex.EncodeToString(h[:])) != 64 {
		t.Fatal("invalid SHA-256 length")
	}
	for _, s := range []string{"../escape", "/absolute", "a//b", ".", "a/./b", "a/../b", "a\\b", ""} {
		if legalPath0377(s) {
			t.Fatalf("accepted traversal %q", s)
		}
	}
}
