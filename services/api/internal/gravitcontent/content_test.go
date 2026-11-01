package gravitcontent

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const profileFixture = `{"title":"Demo","info":"Server","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"minJavaVersion":17,"maxJavaVersion":999,"classLoaderConfig":"SYSTEM_ARGS","classPath":["minecraft.jar"],"update":["minecraft.jar"],"updateVerify":["minecraft.jar"],"updateExclusions":["saves","screenshots","resourcepacks","options.txt"],"settings":{"ram":4096,"autoEnter":false,"fullScreen":false},"limited":false}`

func testZip(t *testing.T, contents map[string]string) ([]byte, inv.Inventory) {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, value := range contents {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(value)); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	raw := buf.Bytes()
	d := sha256.Sum256(raw)
	inventory, e := inv.Inspect(context.Background(), bytes.NewReader(raw), int64(len(raw)), hex.EncodeToString(d[:]))
	if e != nil {
		t.Fatal(e)
	}
	return raw, inventory
}
func TestContentRealFileSelection0337(t *testing.T) {
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json": profileFixture, "updates/demo/minecraft.jar": "jar-bytes", "updates/other/evil.jar": "other", "assets/indexes/index.json": "{}", "libraries/com/example/lib.jar": "lib", "LaunchServer.json": "{}", "modules/unsafe.jar": "must-not-execute", "skins/example.png": "private-image",
	})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if !p.Ready {
		t.Fatalf("unexpected blockers: %+v", p.Blockers)
	}
	if len(p.Files) != 3 {
		t.Fatalf("unexpected staged files: %+v", p.Files)
	}
	if p.FilesSHA256 == "" || len(p.FilesSHA256) != 64 {
		t.Fatal("missing file plan digest")
	}
	for _, f := range p.Files {
		if strings.Contains(f.SourcePath, "unsafe") || strings.Contains(f.SourcePath, "other") || strings.Contains(f.SourcePath, "skins") || strings.HasSuffix(f.SourcePath, "LaunchServer.json") {
			t.Fatalf("source executable or foreign file included: %+v", f)
		}
		content, e := ReadVerifiedFile(context.Background(), bytes.NewReader(raw), int64(len(raw)), f)
		if e != nil || int64(len(content)) != f.Size {
			t.Fatalf("verified stage failed %v", e)
		}
	}
	p2, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil || p2.FilesSHA256 != p.FilesSHA256 {
		t.Fatalf("nondeterministic plan: %v", e)
	}
}
func TestContentRejectsCollisionAndArchiveMutation0337(t *testing.T) {
	raw, invSnapshot := testZip(t, map[string]string{"profiles/demo.json": profileFixture, "updates/demo/minecraft.jar": "one", "clients/demo/minecraft.jar": "two"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), invSnapshot, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready || len(p.Blockers) == 0 {
		t.Fatal("case/path collision was not blocked")
	}
	other := append([]byte(nil), raw...)
	other[len(other)-1] ^= 1
	if _, e = Prepare(context.Background(), bytes.NewReader(other), int64(len(other)), invSnapshot, "profiles/demo.json", "project", "demo", "", "vanilla"); e == nil {
		t.Fatal("modified ZIP matched inventory")
	}
}
func TestContentRejectsCustomBehavior0337(t *testing.T) {
	hostile := strings.Replace(profileFixture, `"limited":false`, `"limited":true`, 1)
	raw, manifest := testZip(t, map[string]string{"profiles/demo.json": hostile, "updates/demo/minecraft.jar": "jar"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), manifest, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready {
		t.Fatal("unportable Gravit permission flag must block import")
	}
}
func TestContentOptionalUnknownAction0337(t *testing.T) {
	hostile := strings.Replace(profileFixture, `"limited":false`, `"limited":false,"updateOptional":[{"name":"bad","actions":[{"type":"execute","command":"rm -rf /"}]}]`, 1)
	raw, manifest := testZip(t, map[string]string{"profiles/demo.json": hostile, "updates/demo/minecraft.jar": "jar"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), manifest, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready || p.Optional == nil || p.Optional.Ready {
		t.Fatalf("unsupported optional action accepted: %+v", p.Optional)
	}
}
func TestContentSafeTargets0337(t *testing.T) {
	for _, p := range []string{"../world", "C:/foo", "/root", "mods\\foo", "a/../b", ".migration/evil"} {
		if safeTarget(p) {
			t.Fatalf("unsafe path accepted %q", p)
		}
	}
}

// 0.44.3: the source install directory is the profile's explicit `dir`, not
// the JSON filename. Each imported byte is authenticated by the MIG03 digest.
func TestContentExplicitClientDirectory0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"dir":"production-pack","limited":false`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/public.json":                  profile,
		"updates/production-pack/minecraft.jar": "correct-jar",
		"updates/public/minecraft.jar":          "WRONG-JAR",
		"clients/public/launcher.jar":           "foreign",
		"libraries/dependency.jar":              "shared-library",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/public.json", "project", "public", "", "vanilla")
	if err != nil || !p.Ready {
		t.Fatalf("explicit dir import failed: %v, %+v", err, p.Blockers)
	}
	if p.SourceDirectory != "production-pack" || len(p.Files) != 2 {
		t.Fatalf("imported wrong source tree: %+v", p)
	}
	for _, file := range p.Files {
		if strings.Contains(file.SourcePath, "/public/") {
			t.Fatalf("wrong client tree copied: %s", file.SourcePath)
		}
		b, err := ReadVerifiedFile(context.Background(), bytes.NewReader(raw), int64(len(raw)), file)
		if err != nil || len(b) == 0 {
			t.Fatalf("failed to read verified file %v", err)
		}
	}
}

func TestContentNeverCopiesPlayerFiles0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"update":["minecraft.jar"]`, `"update":["minecraft.jar","mods"]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":                 profile,
		"updates/demo/minecraft.jar":         "jar",
		"updates/demo/mods/expected.jar":     "mod",
		"updates/demo/mods/.unused":          "dot-file",
		"updates/demo/options.txt":           "player's options",
		"updates/demo/saves/world/level.dat": "player world",
		"updates/demo/screenshots/foo.png":   "user screenshot",
		"updates/demo/unmanaged.jar":         "not in update",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready {
		t.Fatalf("valid client tree blocked: %+v", p.Blockers)
	}
	if len(p.Files) != 2 {
		t.Fatalf("unexpected managed files: %+v", p.Files)
	}
	if len(p.SkippedFiles) != 5 {
		t.Fatalf("skips are not audited: %+v", p.SkippedFiles)
	}
	for _, f := range p.Files {
		if strings.Contains(f.TargetPath, "saves") || strings.Contains(f.TargetPath, "options") || strings.Contains(f.TargetPath, "unmanaged") || strings.Contains(f.TargetPath, "screenshots") {
			t.Fatalf("player data copied: %q", f.TargetPath)
		}
	}
}

func TestContentRejectsMissingExplicitDirectory0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"dir":"renamed","limited":false`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "wrong"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready || !strings.Contains(strings.Join(p.Blockers, " "), "renamed") {
		t.Fatalf("missing explicit directory silently fell back: %+v", p)
	}
}

func TestContentRejectsProtectedClasspath0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"classPath":["minecraft.jar"]`, `"classPath":["saves/evil.jar"]`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/saves/evil.jar": "untrusted", "updates/demo/minecraft.jar": "good"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready || !strings.Contains(strings.Join(p.Blockers, " "), "unsafe classpath") {
		t.Fatalf("protected classpath accepted: %+v", p)
	}
}

func TestContentSourceDirectoryUnsafe0443(t *testing.T) {
	for _, directory := range []string{"../other", "/tmp", ".migration", "a\\b", "C:/local"} {
		profile := strings.Replace(profileFixture, `"limited":false`, `"dir":`+strconv.Quote(directory)+`,"limited":false`, 1)
		raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "test"})
		if _, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla"); err == nil {
			t.Fatalf("unsafe client dir accepted %q", directory)
		}
	}
}

func TestContentStagesOptionalDeclaredFiles0443(t *testing.T) {
	optional := `"updateOptional":[{"name":"Maps","actions":[{"type":"file","files":{"mods/maps.jar":""}}]}],`
	profile := strings.Replace(profileFixture, `"limited":false`, optional+`"limited":false`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":            profile,
		"updates/demo/minecraft.jar":    "main",
		"updates/demo/mods/maps.jar":    "optional-content",
		"updates/demo/mods/unknown.jar": "unapproved-content",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready || p.Optional == nil || !p.Optional.Ready {
		t.Fatalf("optional file not prepared: %v, %+v %+v %+v %+v", err, p.Blockers, p.Optional, p.Files, p.SkippedFiles)
	}
	if len(p.Files) != 2 || len(p.SkippedFiles) != 1 {
		t.Fatalf("unexpected optional staging: %+v", p)
	}
	for _, f := range p.Files {
		if f.TargetPath == "mods/maps.jar" && f.Ownership != "optional" {
			t.Fatal("optional file lost ownership")
		}
		if f.TargetPath == "mods/unknown.jar" {
			t.Fatal("undeclared file included")
		}
	}
}

func TestContentEmptyUpdateDoesNotStageUnmanaged0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"update":["minecraft.jar"]`, `"update":[]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":          profile,
		"updates/demo/minecraft.jar":  "required by classpath",
		"updates/demo/bin/client.exe": "not explicitly managed",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready {
		t.Fatalf("invalid classpath: %v %+v", err, p.Blockers)
	}
	if len(p.Files) != 1 || p.Files[0].TargetPath != "minecraft.jar" || len(p.SkippedFiles) != 1 {
		t.Fatalf("unexpectedly transferred unlisted member: %+v", p)
	}
}
