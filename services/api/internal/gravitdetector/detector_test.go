package gravitdetector

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func archive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	z := zip.NewWriter(&output)
	for name, content := range files {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(content); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return output.Bytes()
}
func launchServer(version string) []byte {
	return []byte(fmt.Sprintf(`{"auth":{"std":{"isDefault":true,"core":{"type":"sql","holder":{"password":"SUPER_SECRET_PASSWORD"},"passwordVerifier":{"type":"bcrypt"}},"textureProvider":{"type":"request","skinURL":"https://example.com/skins"}}},"netty":{"bindAddress":"127.0.0.1"},"env":"STD","version":"%s"}`, version))
}
func serverJar(t *testing.T, v string) []byte {
	t.Helper()
	return archive(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nImplementation-Title: GravitLauncher LaunchServer\r\nImplementation-Version: " + v + "\r\n")})
}
func base(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"installation/LaunchServer.json":        launchServer("5.7.12"),
		"installation/LaunchServerRuntime.json": []byte(`{"serverID":"abc"}`),
		"installation/profiles/fabric.json":     []byte(`{"title":"Test","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","updateOptional":[{"name":"Shaders","actions":[{"type":"file","files":{"mods/a.jar":"mods/a.jar"}}]}]}`),
		"installation/LaunchServer.jar":         serverJar(t, "5.7.12"),
	}
}
func finding(r Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
func TestKnownGravit57Assess0332(t *testing.T) {
	b := archive(t, base(t))
	r, e := Assess(b, "5.7.12")
	if e != nil {
		t.Fatal(e)
	}
	if r.DetectedVersion != "5.7.12" || r.VersionStatus != "recognized" || r.VersionEvidence != "jar-manifest" {
		t.Fatalf("version detection: %+v", r)
	}
	if r.Status != "manual" || r.CutoverAllowed || len(r.Components) != 3 {
		t.Fatalf("unexpected assessment result: %+v", r)
	}
	if !finding(r, "AUTH_REQUIRES_MAPPING") || !finding(r, "OPTIONAL_ACTION_REVIEW") {
		t.Fatalf("missing findings: %+v", r.Findings)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "SUPER_SECRET_PASSWORD") {
		t.Fatal("password leaked in report")
	}
	if again, e := Assess(b, "5.7.12"); e != nil || again.SourceSHA256 != r.SourceSHA256 {
		t.Fatal("nondeterministic source hash")
	}
}
func TestUnknownAuthBlocks0332(t *testing.T) {
	f := base(t)
	f["installation/LaunchServer.json"] = []byte(`{"auth":{"custom":{"isDefault":true,"core":{"type":"ownplugin","apiKey":"HIDDEN"}}}}`)
	r, e := Assess(archive(t, f), "5.7.12")
	if e != nil || r.Status != "blocked" || !finding(r, "UNKNOWN_AUTH_PROVIDER") {
		t.Fatalf("unknown auth allowed %+v %v", r, e)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "HIDDEN") {
		t.Fatal("secret exposed")
	}
}
func TestUnknownOptionalBlocks0332(t *testing.T) {
	f := base(t)
	f["installation/profiles/fabric.json"] = []byte(`{"title":"X","version":"1.20","mainClass":"a.b.Main","updateOptional":[{"actions":[{"type":"shell","command":"echo secret"}]}]}`)
	r, e := Assess(archive(t, f), "5.7.12")
	if e != nil || r.Status != "blocked" || !finding(r, "UNKNOWN_OPTIONAL_ACTION") {
		t.Fatalf("unknown action not blocked %+v %v", r, e)
	}
}
func TestVersionMismatchAndClaim0332(t *testing.T) {
	f := base(t)
	r, e := Assess(archive(t, f), "5.7.11")
	if e != nil || r.VersionStatus != "conflict" || r.Status != "blocked" {
		t.Fatalf("version spoof: %+v %v", r, e)
	}
	delete(f, "installation/LaunchServer.jar")
	r, e = Assess(archive(t, f), "5.7.12")
	if e != nil || r.VersionStatus != "unverified" || r.VersionEvidence != "operator-claim" || r.CutoverAllowed == true {
		t.Fatalf("unverified version: %+v %v", r, e)
	}
	r, e = Assess(archive(t, f), "5.8.0")
	if e != nil || r.VersionStatus != "unsupported" || r.Status != "blocked" {
		t.Fatalf("wrong version supported %+v %v", r, e)
	}
}
func TestInvalidConfigAndZip0332(t *testing.T) {
	f := base(t)
	f["installation/LaunchServer.json"] = []byte(`{"auth":{"std":{"core":`) // broken JSON
	r, e := Assess(archive(t, f), "")
	if e != nil || !finding(r, "INVALID_JSON") || r.Status != "blocked" {
		t.Fatalf("bad config accepted %+v %v", r, e)
	}
	for _, n := range []string{"../LaunchServer.json", "/etc/passwd", "C:/secret"} {
		_, e := Assess(archive(t, map[string][]byte{n: []byte("x")}), "")
		if e == nil {
			t.Errorf("Принят небезопасный путь %q", n)
		}
	}
	if _, e = Assess([]byte("not a zip"), ""); e == nil {
		t.Error("nonzip accepted")
	}
}
func TestSourcePackageIndependentOfModuleExecution0332(t *testing.T) {
	f := base(t)
	f["installation/modules/unsafe.jar"] = []byte("not executed")
	r, e := Assess(archive(t, f), "5.7.12")
	if e != nil {
		t.Fatal(e)
	}
	if !finding(r, "MODULE_REVIEW_REQUIRED") {
		t.Fatalf("custom module not reported %+v", r)
	}
}

func TestWrapperEnvSecretsAndDuplicateKeys0332(t *testing.T) {
	f := base(t)
	f["installation/.env"] = []byte("SERVERWRAPPER_ADDRESS=ws://127.0.0.1:9274\nSERVERWRAPPER_CHECK_SERVER_TOKEN=PRIVATE_SESSION_TOKEN\n")
	r, e := Assess(archive(t, f), "5.7.12")
	if e != nil || !finding(r, "WRAPPER_REENROLL") {
		t.Fatalf("wrapper env undetected %+v %v", r, e)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "PRIVATE_SESSION_TOKEN") {
		t.Fatal("wrapper credential leaked")
	}
	f["installation/LaunchServer.json"] = []byte(`{"auth":{"std":{"isDefault":true,"core":{"type":"sql","type":"unknown"}}}}`)
	r, e = Assess(archive(t, f), "5.7.12")
	if e != nil || !finding(r, "INVALID_JSON") || r.Status != "blocked" {
		t.Fatalf("ambiguous JSON accepted %+v %v", r, e)
	}
}
func TestAmbiguousLaunchServer0332(t *testing.T) {
	f := base(t)
	f["second/LaunchServer.json"] = launchServer("5.7.12")
	r, e := Assess(archive(t, f), "5.7.12")
	if e != nil || !finding(r, "MULTIPLE_LAUNCHSERVERS") || r.Status != "blocked" {
		t.Fatalf("ambiguous source accepted %+v %v", r, e)
	}
}

// Настоящий модпак может превышать старый предел совместимости 64 МиБ. Путь
// запроса должен сканировать его без загрузки всех исходных байтов в память
// процесса.
func TestReaderLargeSource0441(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "source-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z := zip.NewWriter(file)
	for path, data := range base(t) {
		w, err := z.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	large, err := z.CreateHeader(&zip.FileHeader{Name: "installation/updates/fabric/big-library.jar", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	part := bytes.Repeat([]byte("client bundle filler, all bytes checked;"), 32768)
	for n := 0; n < 68; n++ {
		if _, err := large.Write(part); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 64<<20 {
		t.Fatalf("fixture too small: %d", info.Size())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	sha := hex.EncodeToString(digest.Sum(nil))
	r, err := AssessReader(context.Background(), file, info.Size(), sha, "5.7.12")
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceBytes != info.Size() || r.SourceSHA256 != sha || r.Categories["client"] != 1 || len(r.FilesSHA256) != 64 {
		t.Fatalf("missing verified large inventory: %+v", r)
	}
	if r.ServerJarSHA256 == "" || r.DetectedVersion != "5.7.12" || !finding(r, "BINARY_PROVENANCE_NOT_ATTESTED") || r.CutoverAllowed {
		t.Fatalf("unverified binary classified as ready: %+v", r)
	}
	if _, err := AssessReader(context.Background(), file, info.Size(), strings.Repeat("0", 64), "5.7.12"); err == nil {
		t.Fatal("accepted incorrect source digest")
	}
	if again, err := AssessReader(context.Background(), file, info.Size(), sha, "5.7.12"); err != nil || again.FilesSHA256 != r.FilesSHA256 {
		t.Fatalf("large scan not reproducible: %v", err)
	}
}

func TestGravit573CandidateAndSourceCategories0441(t *testing.T) {
	source := base(t)
	source["installation/LaunchServer.jar"] = serverJar(t, "5.7.13")
	source["installation/modules-config/FileAuthSystem/Database.json"] = []byte(`{"uuid":{"username":"Alice"}}`)
	source["installation/modules-config/MyModule/settings.json"] = []byte(`{"token":"SECRET_NOT_IN_REPORT"}`)
	wrapperJar := make([]byte, 3<<20)
	if _, err := rand.New(rand.NewSource(441)).Read(wrapperJar); err != nil {
		t.Fatal(err)
	}
	source["installation/serverwrapper/ServerWrapper.jar"] = wrapperJar
	source["installation/assets/indexes/1.20.json"] = []byte(`{"objects":{}}`)
	source["installation/libraries/example.jar"] = []byte("library")
	source["installation/skins/Alice.png"] = []byte("image")
	report, err := Assess(archive(t, source), "5.7.13")
	if err != nil {
		t.Fatal(err)
	}
	if report.DetectedVersion != "5.7.13" || report.VersionStatus != "recognized" || report.CutoverAllowed || report.Status != "manual" {
		t.Fatalf("unexpected candidate status: %+v", report)
	}
	if report.Categories["authentication"] != 1 || report.Categories["module_config"] != 1 || report.Categories["server_wrapper"] != 1 || report.Categories["asset"] != 1 || report.Categories["library"] != 1 || report.Categories["texture"] != 1 {
		t.Fatalf("source categories incomplete: %+v", report.Categories)
	}
	if strings.Contains(fmt.Sprintf("%+v", report), "SECRET_NOT_IN_REPORT") {
		t.Fatal("configuration secret leaked into report")
	}
	if !finding(report, "BINARY_PROVENANCE_NOT_ATTESTED") {
		t.Fatal("provenance claim missing")
	}
}

func TestReaderCorruptSourceAndCancelled0441(t *testing.T) {
	source := corruptFixture0441(t)
	corrupted := append([]byte(nil), source...)
	pos := bytes.Index(corrupted, []byte("EXACT_BYTES_MATCHED"))
	if pos < 0 {
		t.Fatal("stored ZIP fixture expected")
	}
	corrupted[pos] ^= 0x7f
	sha := sha256.Sum256(corrupted)
	if _, err := AssessReader(context.Background(), bytes.NewReader(corrupted), int64(len(corrupted)), hex.EncodeToString(sha[:]), ""); err == nil {
		t.Fatal("CRC mismatch accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sha = sha256.Sum256(source)
	if _, err := AssessReader(ctx, bytes.NewReader(source), int64(len(source)), hex.EncodeToString(sha[:]), ""); err == nil {
		t.Fatal("cancelled inspection accepted")
	}
}

func corruptFixture0441(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "assets/content", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("EXACT_BYTES_MATCHED")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
