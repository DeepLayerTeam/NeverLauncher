package gravitmodules

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
)

func zipFixture0338(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for n, v := range files {
		f, e := z.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(v); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func inspectFixture0338(t *testing.T, b []byte) (*os.File, inv.Inventory) {
	t.Helper()
	h := sha256.Sum256(b)
	report, e := inv.Inspect(context.Background(), bytes.NewReader(b), int64(len(b)), hex.EncodeToString(h[:]))
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.CreateTemp(t.TempDir(), "source-*.zip")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(b); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { file.Close() })
	return file, report
}
func TestGravitModulesUnknownCriticalBlocking0338(t *testing.T) {
	jar := zipFixture0338(t, map[string][]byte{
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\nImplementation-Title: SENSITIVE_MANIFEST_VALUE\n"),
		"pkg/AuthHook.class":   []byte("\xca\xfe\xba\xbe... pro/gravit/launcher/auth/provider/AuthProvider"),
	})
	source := zipFixture0338(t, map[string][]byte{
		"project/modules/CustomAuth.jar":   jar,
		"project/ServerWrapperConfig.json": []byte(`{"serverName":"lobby","address":"SENSITIVE_ADDRESS","checkServerToken":"SENSITIVE_TOKEN"}`),
		"project/LaunchServer.json":        []byte(`{"auth":{}}`),
	})
	f, snapshot := inspectFixture0338(t, source)
	report, e := Analyze(context.Background(), f, int64(len(source)), snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if report.Ready || report.CutoverAllowed || len(report.Modules) != 1 || !report.Modules[0].AuthHook || len(report.Blockers) != 1 {
		t.Fatalf("unsafe source accepted: %+v", report)
	}
	if len(report.Wrappers) != 1 || report.Wrappers[0].ServerName != "lobby" || !report.Wrappers[0].LegacyTokenPresent {
		t.Fatalf("wrong wrapper migration %+v", report.Wrappers)
	}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"SENSITIVE_MANIFEST_VALUE", "SENSITIVE_TOKEN", "SENSITIVE_ADDRESS"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("secret leaked: %s", secret)
		}
	}
	second, e := Analyze(context.Background(), f, int64(len(source)), snapshot)
	if e != nil {
		t.Fatal(e)
	}
	other, _ := json.Marshal(second)
	if !bytes.Equal(raw, other) {
		t.Fatal("non deterministic report")
	}
}
func TestGravitModulesWrapperInline0338(t *testing.T) {
	src := zipFixture0338(t, map[string][]byte{
		"server/.env": []byte("SERVERWRAPPER_ADDRESS=ws://localhost:9274/api\nSERVERWRAPPER_CHECK_SERVER_TOKEN=private!\n_JAVA_OPTIONS=-Dlauncher.authlib.inlineClass=pro.gravit.launcher.server.ServerWrapperInlineInitializer\n"),
		"other/.env":  []byte("NORMAL_KEY=not-relevant\n"),
	})
	f, inventory := inspectFixture0338(t, src)
	report, e := Analyze(context.Background(), f, int64(len(src)), inventory)
	if e != nil {
		t.Fatal(e)
	}
	if len(report.Wrappers) != 1 || report.Wrappers[0].Mode != "inline" || !report.Ready || report.CutoverAllowed {
		t.Fatalf("bad inline wrapper result %+v", report)
	}
}
func TestGravitModulesTamperRejected0338(t *testing.T) {
	src := zipFixture0338(t, map[string][]byte{"modules/custom.jar": []byte("broken zip")})
	f, snapshot := inspectFixture0338(t, src)
	snapshot.Files[0].SHA256 = strings.Repeat("0", 64)
	if _, e := Analyze(context.Background(), f, int64(len(src)), snapshot); e == nil {
		t.Fatal("altered inventory digest accepted")
	}
	f, snapshot = inspectFixture0338(t, src)
	result, e := Analyze(context.Background(), f, int64(len(src)), snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if result.Ready || len(result.Blockers) != 1 {
		t.Fatalf("invalid jar passed: %+v", result)
	}
}
func TestGravitModulesUnsafeNestedJar0338(t *testing.T) {
	jar := zipFixture0338(t, map[string][]byte{"../escape.class": []byte("x")})
	src := zipFixture0338(t, map[string][]byte{"modules/escape.jar": jar})
	f, inventory := inspectFixture0338(t, src)
	result, e := Analyze(context.Background(), f, int64(len(src)), inventory)
	if e != nil {
		t.Fatal(e)
	}
	if result.Ready || len(result.Blockers) != 1 {
		t.Fatalf("malicious jar not blocked %+v", result)
	}
}

func TestLegacyServerWrapperJAR0338(t *testing.T) {
	jar := zipFixture0338(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\n")})
	source := zipFixture0338(t, map[string][]byte{"ServerWrapper.jar": jar, "config/ServerWrapperConfig.json": []byte(`{"serverName":"hub"}`)})
	f, inventory := inspectFixture0338(t, source)
	result, e := Analyze(context.Background(), f, int64(len(source)), inventory)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Modules) != 1 || result.Modules[0].Implementation != "built_in_equivalent" || result.Modules[0].Status != "manual" || !result.Ready || result.CutoverAllowed {
		t.Fatalf("legacy wrapper misclassified %+v", result)
	}
}
