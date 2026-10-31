package devtools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeTestJar(t *testing.T, signed bool, source string) string {
	t.Helper()
	if _, e := exec.LookPath("javac"); e != nil {
		t.Skip("javac unavailable")
	}
	d := t.TempDir()
	src := filepath.Join(d, "Fixture.java")
	if e := os.WriteFile(src, []byte(source), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("javac", "-g", "Fixture.java")
	cmd.Dir = d
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("javac: %s %v", out, e)
	}
	f, e := os.Create(filepath.Join(d, "fixture.jar"))
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\nMain-Class: Fixture\r\n\r\n")}, {"Fixture.class", readTestFile(t, filepath.Join(d, "Fixture.class"))}} {
		w, e := z.Create(entry.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(entry.data); e != nil {
			t.Fatal(e)
		}
	}
	if signed {
		w, _ := z.Create("META-INF/EXAMPLE.SF")
		w.Write([]byte("Signature-Version: 1.0\n"))
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
	return f.Name()
}
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

const helloSource = `public class Fixture { public static void main(String[] args) { String s="hello"; if(args.length>0) s += args[0]; System.out.println(s); } }`

func TestAnalyzeAndTransformJava(t *testing.T) {
	jar := makeTestJar(t, false, helloSource)
	a, e := AnalyzeJar(jar)
	if e != nil {
		t.Fatal(e)
	}
	if a.Classes != 1 || a.BytecodeMax < 61 || a.Signed {
		t.Fatalf("unexpected jar analysis: %+v", a)
	}
	out := filepath.Join(t.TempDir(), "stripped.jar")
	r, e := StripDebugJar(jar, out)
	if e != nil {
		t.Fatal(e)
	}
	if r.ModifiedClasses != 1 || r.RemovedAttributes < 2 {
		t.Fatalf("debug attributes not stripped: %+v", r)
	}
	for _, p := range []string{jar, out} {
		cmd := exec.Command("java", "-jar", p, "-ok")
		b, e := cmd.CombinedOutput()
		if e != nil || strings.TrimSpace(string(b)) != "hello-ok" {
			t.Fatalf("Java cannot run %s: %s %v", p, b, e)
		}
	}
	if _, e := StripDebugJar(jar, out); e == nil {
		t.Fatal("clobbered existing output")
	}
}
func TestSuspiciousReferenceAndSignatures(t *testing.T) {
	jar := makeTestJar(t, false, `public class Fixture { public static void main(String[] a) throws Exception { Runtime.getRuntime().exec("/bin/echo"); } }`)
	r, e := AnalyzeJar(jar)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range r.Findings {
		if v.Rule == "process-execution" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing process execution indicator: %+v", r)
	}
	signed := makeTestJar(t, true, helloSource)
	r, e = AnalyzeJar(signed)
	if e != nil || !r.Signed {
		t.Fatalf("signature not detected: %+v %v", r, e)
	}
	if _, e := StripDebugJar(signed, filepath.Join(t.TempDir(), "out.jar")); e == nil {
		t.Fatal("transformed signed JAR")
	}
}
func TestJarZipTraversalRejected(t *testing.T) {
	for _, entry := range []string{"../evil.class", "/absolute.class", "a\\evil.class"} {
		t.Run(entry, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.jar")
			f, e := os.Create(p)
			if e != nil {
				t.Fatal(e)
			}
			z := zip.NewWriter(f)
			w, e := z.Create(entry)
			if e != nil {
				t.Fatal(e)
			}
			w.Write([]byte{1, 2, 3})
			z.Close()
			f.Close()
			if _, e := AnalyzeJar(p); e == nil {
				t.Fatal("unsafe filename accepted")
			}
		})
	}
}
func TestRunProcessSanitized(t *testing.T) {
	jar := makeTestJar(t, false, `public class Fixture { public static void main(String[] a) { System.out.println(System.getenv("LAUNCHER_TOKEN")); System.out.println(System.getenv("LAUNCHER_DEVTOOLS_TEST_MODE")); System.out.println(a[0]); } }`)
	t.Setenv("LAUNCHER_TOKEN", "production-secret")
	r, e := RunComponent(context.Background(), ComponentOptions{Jar: jar, Java: "java", Isolation: "process", Timeout: 4 * time.Second, HeapMB: 64, Args: []string{"argument"}})
	if e != nil {
		t.Fatal(e)
	}
	if r.ExitCode != 0 || strings.Contains(r.Stdout, "production-secret") || !strings.Contains(r.Stdout, "null\n1\nargument") {
		t.Fatalf("test process leaked data or args missing: %+v", r)
	}
}
func TestRunTimeout(t *testing.T) {
	jar := makeTestJar(t, false, `public class Fixture { public static void main(String[] a) throws Exception { Thread.sleep(10000); } }`)
	r, e := RunComponent(context.Background(), ComponentOptions{Jar: jar, Java: "java", Isolation: "process", Timeout: 150 * time.Millisecond, HeapMB: 64})
	if e == nil || !r.TimedOut {
		t.Fatalf("test JVM did not time out: %+v %v", r, e)
	}
}
func sendJSON(t *testing.T, client *http.Client, url string, body string, control string) (int, map[string]any) {
	t.Helper()
	r, e := http.NewRequest("POST", url, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	if control != "" {
		r.Header.Set("Authorization", "Bearer "+control)
	}
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var result map[string]any
	if e := json.NewDecoder(resp.Body).Decode(&result); e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, result
}
func TestAuthFixtureIntegration(t *testing.T) {
	f, e := NewFixtureServer("debug-user")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(f.Handler())
	defer server.Close()
	client := server.Client()
	base := server.URL
	status, _ := sendJSON(t, client, base+"/fixture/v1/login", `{"username":"debug-user","password":"wrong"}`, "")
	if status != 401 {
		t.Fatalf("wrong password: %d", status)
	}
	body, _ := json.Marshal(map[string]string{"username": "debug-user", "password": f.Password()})
	status, logged := sendJSON(t, client, base+"/fixture/v1/login", string(body), "")
	if status != 200 {
		t.Fatalf("login failed: %+v", logged)
	}
	token := logged["accessToken"].(string)
	if !strings.HasPrefix(token, TestTokenPrefix) {
		t.Fatal("wrong identity format")
	}
	claims, e := f.Verify(token)
	if e != nil || claims.Subject != "debug-user" {
		t.Fatalf("unexpected claims %+v %v", claims, e)
	}
	body, _ = json.Marshal(map[string]string{"token": token})
	status, active := sendJSON(t, client, base+"/fixture/v1/introspect", string(body), "")
	if status != 200 || active["active"] != true {
		t.Fatalf("introspection failed %+v", active)
	}
	status, _ = sendJSON(t, client, base+"/fixture/v1/revoke", string(body), "")
	if status != 403 {
		t.Fatal("revocation without policy token was allowed")
	}
	status, _ = sendJSON(t, client, base+"/fixture/v1/revoke", string(body), f.ControlToken())
	if status != 200 {
		t.Fatal("authorized revocation failed")
	}
	if _, e := f.Verify(token); e == nil {
		t.Fatal("revoked identity accepted")
	}
	request, _ := http.NewRequest("GET", base+"/fixture/v1/events", nil)
	request.Header.Set("Authorization", "Bearer "+f.ControlToken())
	resp, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	var events struct {
		Events []AuthEvent `json:"events"`
	}
	e = json.NewDecoder(resp.Body).Decode(&events)
	resp.Body.Close()
	if e != nil || len(events.Events) < 4 {
		t.Fatalf("missing auth events: %+v %v", events, e)
	}
	status, _ = sendJSON(t, client, base+"/fixture/v1/issue", `{"subject":"another","scopes":["test:read"],"ttlSeconds":60}`, "")
	if status != 403 {
		t.Fatal("issue without control token allowed")
	}
	status, issued := sendJSON(t, client, base+"/fixture/v1/issue", `{"subject":"another","scopes":["test:read"],"ttlSeconds":60}`, f.ControlToken())
	if status != 200 {
		t.Fatalf("issue failed: %+v", issued)
	}
}
func TestAuthExpiryAndListener(t *testing.T) {
	f, e := NewFixtureServer("fixture")
	if e != nil {
		t.Fatal(e)
	}
	f.now = func() time.Time { return time.Unix(10000, 0) }
	token, e := f.Issue("debug", []string{"test:read"}, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	f.now = func() time.Time { return time.Unix(10061, 0) }
	if _, e := f.Verify(token); e == nil {
		t.Fatal("expired token accepted")
	}
	for _, addr := range []string{"0.0.0.0:0", "127.0.0.2.local:0", "[::]:0"} {
		if l, e := ListenFixture(addr, f); e == nil {
			l.Close()
			t.Fatalf("unsafe bind %q", addr)
		}
	}
	l, e := ListenFixture("127.0.0.1:0", f)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
}
func TestAuthTokenNotProductionJWT(t *testing.T) {
	f, _ := NewFixtureServer("tester")
	token, _ := f.Issue("a", nil, 30*time.Second)
	if strings.Count(token, ".") != 3 {
		t.Fatalf("unexpected debug token shape: %s", token[:20])
	}
	parts := strings.Split(token, ".")
	if parts[0] != "nltest" || parts[1] != "v1" {
		t.Fatal("not a test namespace")
	}
	_, err := f.Verify(token + "x")
	if err == nil {
		t.Fatal("tampered test token accepted")
	}
}

var _ = bytes.MinRead
var _ = fmt.Sprint
