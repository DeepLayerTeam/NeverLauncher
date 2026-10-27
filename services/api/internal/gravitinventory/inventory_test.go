package gravitinventory

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func fixture0333(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range files {
		f, e := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(data)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}
func analyze0333(t *testing.T, b []byte) Inventory {
	t.Helper()
	h := sha256.Sum256(b)
	v, e := Inspect(context.Background(), bytes.NewReader(b), int64(len(b)), hex.EncodeToString(h[:]))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestInventoryExportRoundtrip0333(t *testing.T) {
	data := fixture0333(t, map[string]string{
		"project/LaunchServer.json":     `{"auth":{"default":{"core":{"type":"sql","password":"DO_NOT_EXPORT_IN_REPORT"},"textureProvider":{"type":"local"}}}}`,
		"project/profiles/vanilla.json": `{"title":"Vanilla","version":"1.21","mainClass":"java.Main","servers":[{"name":"one","address":"private-host"}],"updateOptional":[{"actions":[{"type":"file"},{"type":"jvmArgs"}]}]}`,
		"project/assets/objects/aabb":   "asset bytes",
		"project/libraries/foo.jar":     "fake jar data",
		"project/modules/custom.jar":    "opaque jar data",
		"project/skins/player.png":      "texture data",
		"project/private.key":           "MUST_NOT_LEAK",
	})
	inv := analyze0333(t, data)
	if len(inv.Files) != 7 || inv.SourceEntries != 7 || inv.ServerReferences != 1 || inv.AuthProviders["sql"] != 1 || inv.OptionalActions["file"] != 1 || inv.Categories["asset"] != 1 || inv.Categories["key"] != 1 {
		t.Fatalf("wrong parsed inventory %+v", inv)
	}
	serialized, e := json.Marshal(inv)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(serialized, []byte("DO_NOT_EXPORT_IN_REPORT")) || bytes.Contains(serialized, []byte("MUST_NOT_LEAK")) || bytes.Contains(serialized, []byte("private-host")) {
		t.Fatal("secret leaked to database report")
	}
	var first, second bytes.Buffer
	for _, b := range []*bytes.Buffer{&first, &second} {
		if e := Export(context.Background(), b, bytes.NewReader(data), int64(len(data)), inv); e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("export not deterministic")
	}
	archive, e := zip.NewReader(bytes.NewReader(first.Bytes()), int64(first.Len()))
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range archive.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		v, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		if f.Name == ManifestPath {
			if !bytes.Contains(v, []byte(inv.SourceSHA256)) {
				t.Fatal("manifest source hash missing")
			}
			continue
		}
		if f.Name == "project/private.key" && string(v) != "MUST_NOT_LEAK" {
			t.Fatal("export altered secret source bytes")
		}
	}
	if len(archive.File) != len(inv.Files)+1 {
		t.Fatal("export not complete")
	}
}
func TestInventoryRejectsHostileZIP0333(t *testing.T) {
	for _, name := range []string{"../secret.txt", "/absolute/file.txt", "C:/drive.txt", "folder/../file", ".never-migration/inventory.json", ".Never-Migration/INVENTORY.JSON", "a\\b", "a//b", "a\x00b"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			b := fixture0333(t, map[string]string{name: "payload"})
			h := sha256.Sum256(b)
			if _, e := Inspect(context.Background(), bytes.NewReader(b), int64(len(b)), hex.EncodeToString(h[:])); e == nil {
				t.Fatalf("accepted %q", name)
			}
		})
	}
}
func TestInventoryRejectsDuplicateEntries0333(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, n := range []string{"Profiles/A.json", "profiles/a.json"} {
		f, e := w.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = f.Write([]byte("{}"))
	}
	_ = w.Close()
	h := sha256.Sum256(b.Bytes())
	if _, e := Inspect(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()), hex.EncodeToString(h[:])); e == nil {
		t.Fatal("case-insensitive collision accepted")
	}
}
func TestInventoryDetectsCRCAndMalformedConfig0333(t *testing.T) {
	b := fixture0333(t, map[string]string{"LaunchServer.json": `{"auth":{"a":{},"a":{}}}`})
	h := sha256.Sum256(b)
	if _, e := Inspect(context.Background(), bytes.NewReader(b), int64(len(b)), hex.EncodeToString(h[:])); e == nil {
		t.Fatal("duplicate keys accepted")
	}
	good := fixture0333(t, map[string]string{"assets/file": "abcdefg0123456789"})
	damaged := append([]byte{}, good...)
	pos := bytes.Index(damaged, []byte("abcdefg0123456789"))
	if pos < 0 {
		t.Fatal("cannot locate fixture")
	}
	damaged[pos] ^= 0x11
	h = sha256.Sum256(damaged)
	if _, e := Inspect(context.Background(), bytes.NewReader(damaged), int64(len(damaged)), hex.EncodeToString(h[:])); e == nil {
		t.Fatal("corrupted stored ZIP accepted")
	}
}
func TestInventoryChangedSourceRejected0333(t *testing.T) {
	one := fixture0333(t, map[string]string{"assets/one.txt": "data"})
	two := fixture0333(t, map[string]string{"assets/one.txt": "changed"})
	inv := analyze0333(t, one)
	var out bytes.Buffer
	if e := Export(context.Background(), &out, bytes.NewReader(two), int64(len(two)), inv); e == nil {
		t.Fatal("export accepted changed source")
	}
	if out.Len() != 0 {
		t.Fatal("wrote bytes despite mismatch")
	}
}
func TestInventorySpoolPrivate0333(t *testing.T) {
	f, n, h, e := Spool(context.Background(), strings.NewReader("source"))
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Mode().Perm() != 0600 || n != 6 || len(h) != 64 {
		t.Fatalf("unsafe spool n=%d mode=%v err=%v", n, st.Mode(), e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, e := Spool(ctx, strings.NewReader("data")); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel ignored: %v", e)
	}
}
