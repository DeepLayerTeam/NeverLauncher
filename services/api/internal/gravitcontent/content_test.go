package gravitcontent

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
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
	for _, p := range []string{"../world", "C:/foo", "/root", "mods\\foo", "a/../b", ".never-migration/evil"} {
		if safeTarget(p) {
			t.Fatalf("unsafe path accepted %q", p)
		}
	}
}
