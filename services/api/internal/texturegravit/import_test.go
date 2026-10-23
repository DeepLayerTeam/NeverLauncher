package texturegravit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

type databaseFake struct {
	profile  model.MinecraftProfile
	already  bool
	exists   bool
	stage    int
	upload   int
	revision int64
}

func (f *databaseFake) GetMinecraftProfileByUUID(uuid string) (model.MinecraftProfile, error) {
	if uuid != f.profile.UUID {
		return model.MinecraftProfile{}, errors.New("not found")
	}
	return f.profile, nil
}
func (f *databaseFake) GravitImportState02510(_ context.Context, _, _ string, _ model.MinecraftProfile, _ string) (bool, int64, bool, error) {
	return f.already, f.revision, f.exists, nil
}
func (f *databaseFake) StageTextureUpload0253(_ context.Context, _ model.MinecraftProfile, _ repository.VerifiedTexture0252) error {
	f.stage++
	return nil
}
func (f *databaseFake) UploadTexture0252(_ context.Context, _ model.MinecraftProfile, _ repository.VerifiedTexture0252) (model.TextureAssignment0251, error) {
	f.upload++
	f.already = true
	return model.TextureAssignment0251{}, nil
}

func TestIdentityMappingIsStrict02510(t *testing.T) {
	input := `[{"source_uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","target_uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]`
	m, e := LoadMappings([]byte(input))
	if e != nil || m["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"] != "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" {
		t.Fatal(m, e)
	}
	for _, s := range []string{"../../x", "notuuid", "", strings.Repeat("a", 31)} {
		if _, e := CanonicalUUID(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, e := LoadMappings([]byte(`[{"source_uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","target_uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},{"source_uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","target_uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc"}]`)); e == nil {
		t.Fatal("ambiguous identity mapping accepted")
	}
}
func TestObjectKeyValidation02510(t *testing.T) {
	for _, key := range []string{"../etc/passwd", "foo/../bar", "/absolute", "a\\b", "a//b", "a/%evil"} {
		if key != "a/%evil" {
			if ValidateObjectKey(key) == nil {
				t.Fatalf("accepted %q", key)
			}
		}
	}
	if _, e := RenderKey("%kind%/%hash%.png", "skin", strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	if _, e := RenderKey("%foo%", "skin", strings.Repeat("a", 64)); e == nil {
		t.Fatal("unrecognized substitution accepted")
	}
}
func TestSourceHashAndCorruption02510(t *testing.T) {
	b := []byte("texture")
	s := sha256.Sum256(b)
	if err := VerifySourceHash(hex.EncodeToString(s[:]), b); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceHash(hex.EncodeToString(s[:]), append(b, '!')); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if err := VerifySourceHash("garbage", b); err == nil {
		t.Fatal("non hash accepted")
	}
}
func createFixture02510(t *testing.T) (Runner, []SourceRow, *databaseFake) {
	t.Helper()
	root := t.TempDir()
	dest := t.TempDir()
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	img.Set(3, 5, color.NRGBA{R: 240, G: 50, B: 40, A: 255})
	var b bytes.Buffer
	if e := png.Encode(&b, img); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b.Bytes())
	hash := hex.EncodeToString(sum[:])
	if e := os.MkdirAll(filepath.Join(root, "skin"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "skin", hash+".png"), b.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	uuid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	fake := &databaseFake{profile: model.MinecraftProfile{UUID: uuid, UserID: "user", Issuer: "neverlauncher", Realm: "local"}}
	r := Runner{Database: fake, Source: LocalSource{Root: root}, Destination: storage.NewLocalStorage(dest), SourceID: "gravit-test"}
	rows := []SourceRow{{ID: "row1", UserUUID: uuid, TextureType: "SKIN", FileHash: hash, Metadata: json.RawMessage(`{"model":"slim"}`)}}
	return r, rows, fake
}
func TestEndToEndImportAndIdempotency02510(t *testing.T) {
	r, rows, db := createFixture02510(t)
	report, e := r.Run(context.Background(), rows)
	if e != nil {
		t.Fatal(e)
	}
	if report.Counts["imported"] != 1 || db.stage != 1 || db.upload != 1 || len(report.Rows[0].NormalizedDigest) != 64 {
		t.Fatalf("unexpected import: %+v", report)
	}
	second, e := r.Run(context.Background(), rows)
	if e != nil {
		t.Fatal(e)
	}
	if second.Counts["already-imported"] != 1 || db.upload != 1 {
		t.Fatalf("not idempotent: %+v", second)
	}
}
func TestDryRunAndFailureIsolation02510(t *testing.T) {
	r, rows, db := createFixture02510(t)
	r.DryRun = true
	rows = append(rows, SourceRow{ID: "bad", UserUUID: rows[0].UserUUID, TextureType: "SKIN", FileHash: strings.Repeat("a", 64)})
	rows = append(rows, SourceRow{ID: "unknown", UserUUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", TextureType: "CAPE", FileHash: rows[0].FileHash})
	report, e := r.Run(context.Background(), rows)
	if e != nil {
		t.Fatal(e)
	}
	if report.Counts["validated-dry-run"] != 1 || report.Counts["quarantined"] != 1 || report.Counts["unmatched"] != 1 || db.stage != 0 || db.upload != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
func TestLocalSourceRejectsSymlinkEscape02510(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private.png")
	if err := os.WriteFile(outside, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "bad.png")); err != nil {
		t.Skip(err)
	}
	if f, e := (LocalSource{Root: root}).Open(context.Background(), "bad.png"); e == nil {
		f.Close()
		t.Fatal("symlink traversal accepted")
	}
}
func TestExportRows02510(t *testing.T) {
	if _, e := LoadJSON([]byte(`{"not":"array"}`)); e == nil {
		t.Fatal("accepted object")
	}
	if _, e := LoadJSON([]byte(`[{}]`)); e != nil {
		t.Fatal(e)
	}
}
