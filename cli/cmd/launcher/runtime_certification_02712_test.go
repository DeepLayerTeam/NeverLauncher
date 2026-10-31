package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRuntimeCertification02712RejectsFalseProbe(t *testing.T) {
	plan := factoryPlan0271{MinecraftVersion: "1.21.1", Loader: "vanilla", Java: factoryJava0271{Major: 21}, Launch: factoryLaunch0271{MainClass: "net.minecraft.client.main.Main"}}
	good := factoryProbe02712{Status: "passed", MinecraftVersion: "1.21.1", MainClass: plan.Launch.MainClass, RequiredJavaMajor: 21, DetectedJavaMajor: 21, ClasspathEntries: 3, TimedOut: true, RuntimeSeconds: 20}
	goodLog := []byte("Runtime ...\n--- process output ---\n[main/INFO] LWJGL version 3.3\n")
	if err := certValidateProbe02712(plan, "1.21.1", good, goodLog, 30); err == nil {
		t.Fatal("legacy timeout/marker accepted as runtime readiness")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*factoryProbe02712)
		log    []byte
	}{
		{"not actually started", func(p *factoryProbe02712) { p.Status = "failed" }, goodLog},
		{"wrong Java", func(p *factoryProbe02712) { p.DetectedJavaMajor = 17 }, goodLog},
		{"wrong main class", func(p *factoryProbe02712) { p.MainClass = "Fake" }, goodLog},
		{"no classpath", func(p *factoryProbe02712) { p.ClasspathEntries = 0 }, goodLog},
		{"early stalled", func(p *factoryProbe02712) { p.RuntimeSeconds = 1 }, goodLog},
		{"instant crash", func(p *factoryProbe02712) { p.TimedOut = false; p.Success = false }, goodLog},
		{"header only", func(p *factoryProbe02712) {}, []byte("Minecraft: 1.21.1\n--- process output ---\njava process never started\n")},
		{"no stdout marker", func(p *factoryProbe02712) {}, []byte("[main/INFO] LWJGL version 3.3\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := good
			tc.mutate(&p)
			if err := certValidateProbe02712(plan, "1.21.1", p, tc.log, 30); err == nil {
				t.Fatal("false success accepted")
			}
		})
	}
}
func TestRuntimeCertification02712SignedEndToEndMaterializerAndTamper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture runtime; Windows verified by native CI")
	}
	clientJar := []byte("fixture-client")
	asset := []byte("fixture-asset")
	hash := sha1hex(asset)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			meta := fixtureFactoryMetadata0271("http://"+r.Host, "fixture-1", clientJar, asset)
			_ = json.NewEncoder(w).Encode(MojangVersionManifest{Latest: map[string]string{"release": "fixture-1"}, Versions: []MojangManifestVersion{{ID: "fixture-1", Type: "release", URL: "http://" + r.Host + "/version.json", SHA1: sha1hex(meta)}}})
		case "/version.json":
			w.Write(fixtureFactoryMetadata0271("http://"+r.Host, "fixture-1", clientJar, asset))
		case "/asset-index.json":
			w.Write(fixtureFactoryAssets0271(asset))
		case "/client.jar":
			w.Write(clientJar)
		case "/assets/" + hash[:2] + "/" + hash:
			w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	tmp := t.TempDir()
	client := filepath.Join(tmp, "client")
	_, err := executeFactoryBuild0271(context.Background(), factoryBuildOptions0271{Loader: "vanilla", Minecraft: "latest-release", ClientDir: client, VersionManifest: server.URL + "/manifest.json", AssetBaseURL: server.URL + "/assets", HTTPClient: server.Client(), Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true})
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(tmp, "signing.key")
	pub := filepath.Join(tmp, "signing.pub")
	if err := factoryCertKeygen02712(key, pub); err != nil {
		t.Fatal(err)
	}
	if err := factoryCertKeygen02712(key, pub); err == nil {
		t.Fatal("key overwrite accepted")
	}
	runtimePath := filepath.Join(tmp, "fake-runtime")
	runtimeScript := `#!/bin/sh
while [ "$#" -gt 0 ]; do
case "$1" in
--root) root="$2"; shift 2;;
--version) version="$2"; shift 2;;
*) shift;;
esac
done
mkdir -p "$root/logs"
printf '%s\n' '--- process output ---' 'Minecraft client initialized LWJGL version 3.3' > "$root/logs/e2e.log"
printf '{"status":"passed","minecraftVersion":"%s","mainClass":"net.minecraft.client.main.Main","requiredJavaMajor":21,"detectedJavaMajor":21,"classpathEntries":1,"timedOut":true,"success":false,"logPath":"%s/logs/e2e.log","runtimeSeconds":20}\n' "$version" "$root"
`
	if err := os.WriteFile(runtimePath, []byte(runtimeScript), 0700); err != nil {
		t.Fatal(err)
	}
	javaPath := filepath.Join(tmp, "java")
	if err := os.WriteFile(javaPath, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runtimeSHA, err := certHashFile02712(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tmp, "actual-cert.json")
	if _, err = certRun02712(context.Background(), client, runtimePath, javaPath, strings.Repeat("0", 64), key, file, 20); err == nil {
		t.Fatal("unapproved runtime executable accepted")
	}
	// Even a valid owner signing key cannot turn a synthetic LWJGL marker and
	// timeout into menu/renderer readiness. No certificate is written.
	if _, err := certRun02712(context.Background(), client, runtimePath, javaPath, runtimeSHA, key, file, 20); err == nil {
		t.Fatal("synthetic startup probe was certified")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("legacy certification left a supposedly valid artifact: %v", err)
	}
}
func TestRuntimeCertification02712HostAndPaths(t *testing.T) {
	if err := certHostTarget02712(currentVanillaTarget()); err != nil {
		t.Fatal(err)
	}
	wrong := currentVanillaTarget()
	wrong.OS = "never-os"
	if err := certHostTarget02712(wrong); err == nil {
		t.Fatal("cross-target runtime certification accepted")
	}
	if _, err := certResolveExecutable02712(""); err == nil {
		t.Fatal("empty executable accepted")
	}
	if err := factoryCertKeygen02712("", ""); err == nil {
		t.Fatal("empty key paths accepted")
	}
}

func TestRuntimeCertification02712MatrixRejectsMissingOrUnsigned(t *testing.T) {
	root := t.TempDir()
	matrix := filepath.Join(root, "matrix.json")
	valid := `{"schema":"launcher.factory.certification-matrix.v1","targets":[{"id":"vanilla-linux","loader":"vanilla","minecraft":"1.21.1","os":"linux","arch":"x86_64","clientDir":"not-found","certificate":"not-found.json"}]}`
	if err := os.WriteFile(matrix, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := certifyMatrix02712(matrix, "missing.pub", filepath.Join(root, "report.json"), false)
	if err == nil || report.Status != "failed" || report.Failed != 1 {
		t.Fatalf("matrix accepted missing runtime proof: %+v %v", report, err)
	}
	if _, err := os.Stat(filepath.Join(root, "report.json")); err != nil {
		t.Fatalf("missing failure report: %v", err)
	}
	if _, err := certifyMatrix02712(matrix, "missing.pub", "", true); err == nil {
		t.Fatal("matrix without five required families accepted")
	}
	if err := os.WriteFile(matrix, []byte(strings.Replace(valid, `"vanilla-linux"`, `"../escape"`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := certifyMatrix02712(matrix, "missing.pub", "", false); err == nil {
		t.Fatal("unsafe target ID accepted")
	}
}
