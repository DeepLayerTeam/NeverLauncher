package gravitdetector

import (
	"archive/zip"
	"bytes"
	"fmt"
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
			t.Errorf("unsafe path %q accepted", n)
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
