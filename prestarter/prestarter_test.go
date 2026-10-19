package prestarter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeArtifact(data []byte, uri string) Artifact {
	sum := sha256.Sum256(data)
	return Artifact{URL: uri, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}
func identityConfig(parts map[string][]byte) Config {
	t := Target{OS: runtime.GOOS, Arch: runtime.GOARCH}
	for _, name := range []string{"neverruntime", "desktop", "neverguard"} {
		t.Components = append(t.Components, Component{Name: name, Artifact: fakeArtifact(parts[name], "https://example.invalid/"+name)})
	}
	return Config{SchemaVersion: "1.0", ProjectID: "hello", ProfileID: "vanilla", Channel: "stable", ProfilePublicKey: strings.Repeat("a", 64), Manifest: fakeArtifact(parts["profile-manifest.json"], "https://example.invalid/profile-manifest.json"), JavaManifest: fakeArtifact(parts["managed-jre/manifest.json"], "https://example.invalid/java-manifest.json"), Targets: []Target{t}}
}
func generateConfig(t *testing.T, cfg Config) ([]byte, string) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	payload, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	env, e := SignedEnvelope(payload, private)
	if e != nil {
		t.Fatal(e)
	}
	return env, hex.EncodeToString(public)
}
func baseParts() map[string][]byte {
	return map[string][]byte{
		"neverruntime":              []byte("#!/bin/sh\ncase \"$1\" in\nverify) echo '{\"status\":\"ready\"}' ;;\njava) echo '{\"javaExecutable\":\"/verified/runtime/bin/java\",\"majorVersion\":21,\"distribution\":\"temurin\"}' ;;\nsync-local) echo '{\"status\":\"ready\"}' ;;\nlaunch) echo '{\"status\":\"ready\",\"success\":true}' ;;\n*) exit 7 ;;\nesac\n"),
		"desktop":                   []byte("#!/bin/sh\nexit 0\n"),
		"neverguard":                []byte("#!/bin/sh\nexit 0\n"),
		"profile-manifest.json":     []byte(`{"projectId":"hello","profileId":"vanilla","channel":"stable","runtime":{"java":{"majorVersion":21,"distribution":"temurin"},"launch":{"offlineMode":true}}}`),
		"managed-jre/manifest.json": []byte(`{"schemaVersion":"1.0","targets":[]}`),
	}
}
func makeOfflineFixture(t *testing.T, root string, parts map[string][]byte) (Options, Config) {
	t.Helper()
	dir := filepath.Join(root, "offline")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for name, content := range parts {
		path := filepath.Join(dir, "components", name)
		if name == "profile-manifest.json" || strings.HasPrefix(name, "managed-jre/") {
			path = filepath.Join(dir, name)
		} else {
			path = filepath.Join(dir, "components", ComponentName(name))
		}
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, content, 0700); e != nil {
			t.Fatal(e)
		}
	}
	cfg := identityConfig(parts)
	env, key := generateConfig(t, cfg)
	cfgPath := filepath.Join(root, "bootstrap-config.json")
	if e := os.WriteFile(cfgPath, env, 0600); e != nil {
		t.Fatal(e)
	}
	return Options{ConfigPath: cfgPath, Root: filepath.Join(root, "install"), OfflineDir: dir, Offline: true, TrustedKey: key, NoDesktop: true}, cfg
}
func TestSignedConfigCannotBeTamperedWith(t *testing.T) {
	cfg := identityConfig(baseParts())
	env, key := generateConfig(t, cfg)
	if _, _, e := VerifyEnvelope(env, key); e != nil {
		t.Fatal(e)
	}
	bad := append([]byte(nil), env...)
	var s Envelope
	if e := json.Unmarshal(bad, &s); e != nil {
		t.Fatal(e)
	}
	s.Signature = strings.Repeat("0", 128)
	bad, _ = json.Marshal(s)
	if _, _, e := VerifyEnvelope(bad, key); e == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, _, e := VerifyEnvelope(env, strings.Repeat("0", 64)); e == nil {
		t.Fatal("foreign root accepted")
	}
	cfg.Targets[0].Components[0].URL = "http://localhost/binary"
	unsigned, _ := json.Marshal(cfg)
	if _, e := SignedEnvelope(unsigned, ed25519.NewKeyFromSeed(make([]byte, 32))); e == nil {
		t.Fatal("HTTP downgrade accepted")
	}
}
func TestOfflineFreshInstallAndVerifiedRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake POSIX runtime helper requires sh; Windows coverage needs native binaries")
	}
	temp := t.TempDir()
	parts := baseParts()
	opts, cfg := makeOfflineFixture(t, temp, parts)
	opts.LaunchProfile = true
	opts.Username = "TestPlayer"
	if e := Run(context.Background(), opts); e != nil {
		t.Fatal("clean bootstrap:", e)
	}
	recordDir := filepath.Join(opts.Root, "launcher")
	var state activeRecord
	slot := filepath.Join(recordDir, "active-1.json")
	raw, e := os.ReadFile(slot)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &state); e != nil {
		t.Fatal(e)
	}
	if state.Digest == "" || state.Generation != 1 {
		t.Fatal("invalid initial committed pointer", state)
	}
	if e := Run(context.Background(), opts); e != nil {
		t.Fatal("repeated offline install:", e)
	}
	raw, e = os.ReadFile(slot)
	if e != nil {
		t.Fatal(e)
	}
	var again activeRecord
	json.Unmarshal(raw, &again)
	if again.Generation != 1 {
		t.Fatal("same release unexpectedly updated pointer")
	}
	// Corrupt a signed component. Repair must restore from verified cache
	// without deleting the unrelated game/user-owned data.
	userFile := filepath.Join(opts.Root, "profiles", "hello", "vanilla", "saves", "my-world.dat")
	if e = os.MkdirAll(filepath.Dir(userFile), 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(userFile, []byte("player save"), 0600)
	component := filepath.Join(recordDir, "releases", state.Release, ComponentName("neverguard"))
	if e = os.WriteFile(component, []byte("corrupted"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = Run(context.Background(), opts); e != nil {
		t.Fatal("recovery from corrupted binary:", e)
	}
	if !hashFile(component, cfg.Targets[0].Components[2].Artifact) {
		t.Fatal("component not restored")
	}
	save, e := os.ReadFile(userFile)
	if e != nil || string(save) != "player save" {
		t.Fatal("user file lost")
	}
}
func TestFailedNewReleaseKeepsOldActive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper test")
	}
	temp := t.TempDir()
	parts := baseParts()
	opts, _ := makeOfflineFixture(t, temp, parts)
	if e := Run(context.Background(), opts); e != nil {
		t.Fatal(e)
	}
	old, _ := os.ReadFile(filepath.Join(opts.Root, "launcher", "active-1.json"))
	var oldRecord activeRecord
	json.Unmarshal(old, &oldRecord)
	parts["desktop"] = []byte("#!/bin/sh\nexit 2\n")
	cfg := identityConfig(parts)
	signed, key := generateConfig(t, cfg)
	os.WriteFile(opts.ConfigPath, signed, 0600)
	opts.TrustedKey = key
	// No new signed matching desktop binary available -> must not switch.
	if e := Run(context.Background(), opts); e == nil {
		t.Fatal("missing component accepted")
	}
	check, err := os.ReadFile(filepath.Join(opts.Root, "launcher", "active-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(check) != string(old) {
		t.Fatal("old committed pointer changed despite install failure")
	}
}
func TestDownloadRangeResumeAndBadRangeInvalidates(t *testing.T) {
	data := []byte(strings.Repeat("ABCDEF0123456789", 32768))
	checksum := fakeArtifact(data, "https://placeholder.invalid/content")
	var count atomic.Int64
	var sawRange atomic.Bool
	var failFirst atomic.Bool
	failFirst.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if rng := r.Header.Get("Range"); rng != "" {
			sawRange.Store(true)
			if r.Header.Get("If-Range") != "\"v1\"" {
				t.Errorf("wrong If-Range: %q", r.Header.Get("If-Range"))
			}
			var start int64
			fmt.Sscanf(rng, "bytes=%d-", &start)
			w.Header().Set("ETag", "\"v1\"")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
			w.WriteHeader(206)
			w.Write(data[start:])
			return
		}
		w.Header().Set("ETag", "\"v1\"")
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		if failFirst.CompareAndSwap(true, false) {
			w.WriteHeader(200)
			w.Write(data[:len(data)/2])
			return
		}
		w.WriteHeader(200)
		w.Write(data)
	}))
	defer server.Close()
	checksum.URL = server.URL + "/content"
	s, e := newStorage(filepath.Join(t.TempDir(), "cache"), "", false)
	if e != nil {
		t.Fatal(e)
	}
	s.http = server.Client()
	got, e := s.artifact(context.Background(), checksum, "")
	if e != nil {
		t.Fatal(e)
	}
	if !hashFile(got, checksum) || !sawRange.Load() || count.Load() != 2 {
		t.Fatalf("resume not used: requests=%d range=%v", count.Load(), sawRange.Load())
	}
}
func TestMalformed206NeverJoinsOldBytes(t *testing.T) {
	data := []byte(strings.Repeat("G", 1000))
	a := fakeArtifact(data, "https://placeholder.invalid/content")
	var num atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := num.Add(1)
		w.Header().Set("ETag", "\"v1\"")
		if n == 1 {
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(200)
			w.Write(data[:250])
			return
		}
		if n == 2 {
			w.Header().Set("Content-Range", "bytes 1-999/1000")
			w.WriteHeader(206)
			w.Write(data[1:])
			return
		}
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.Write(data)
	}))
	defer server.Close()
	a.URL = server.URL + "/content"
	s, _ := newStorage(filepath.Join(t.TempDir(), "cache"), "", false)
	s.http = server.Client()
	got, e := s.artifact(context.Background(), a, "")
	if e != nil {
		t.Fatal(e)
	}
	if !hashFile(got, a) || num.Load() != 3 {
		t.Fatal("invalid range not discarded", num.Load())
	}
}
func TestManifestIntegrityRejectsWrongBytes(t *testing.T) {
	data := []byte(`{"status":"fake"}`)
	a := fakeArtifact(data, "https://placeholder.invalid")
	dir := t.TempDir()
	s, _ := newStorage(dir, "", true)
	if e := os.MkdirAll(filepath.Join(dir, "cache", "sha256", a.SHA256[:2]), 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(s.objectPath(a), []byte(strings.Repeat("x", len(data))), 0600)
	if _, e := s.artifact(context.Background(), a, ""); e == nil {
		t.Fatal("corrupted object accepted offline")
	}
}
func TestProcessLockSerializesSameRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, e := acquireProcessLock(path)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		second, e := acquireProcessLock(path)
		if e == nil {
			second.Close()
		}
	}()
	select {
	case <-done:
		t.Fatal("acquired locked file twice")
	default:
	}
	first.Close()
	<-done
}
func TestNoUnboundedTransferAccepted(t *testing.T) {
	body := []byte(strings.Repeat("a", 100))
	a := fakeArtifact(body[:10], "https://placeholder.invalid")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); io.WriteString(w, string(body)) }))
	defer srv.Close()
	a.URL = srv.URL + "/file"
	s, _ := newStorage(filepath.Join(t.TempDir(), "cache"), "", false)
	s.http = srv.Client()
	if _, e := s.artifact(context.Background(), a, ""); e == nil {
		t.Fatal("oversize streamed body accepted")
	}
}

func TestDesktopReceivesSignedFirstRunBinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX Desktop probe")
	}
	root := t.TempDir()
	parts := baseParts()
	parts["desktop"] = []byte("#!/bin/sh\nprintf '%s' \"$NEVERLAUNCHER_CONFIG_DIR\" > \"$NEVERLAUNCHER_CONFIG_DIR/desktop-started\"\n")
	opts, _ := makeOfflineFixture(t, root, parts)
	opts.NoDesktop = false
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(opts.Root, ".neverlauncher-prestarter", "desktop-config")
	raw, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err = json.Unmarshal(raw, &binding); err != nil {
		t.Fatal(err)
	}
	if binding["projectId"] != "hello" || binding["profileId"] != "vanilla" || binding["pinnedPublicKey"] != strings.Repeat("a", 64) {
		t.Fatalf("invalid Desktop configuration: %v", binding)
	}
	var marker []byte
	for i := 0; i < 30; i++ {
		marker, err = os.ReadFile(filepath.Join(configDir, "desktop-started"))
		if err == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err != nil || string(marker) != configDir {
		t.Fatalf("Desktop did not launch with verified first-run configuration: %v", err)
	}
}
func TestRollbackIfSignedProfileCannotBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper test")
	}
	root := t.TempDir()
	parts := baseParts()
	opts, cfg := makeOfflineFixture(t, root, parts)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	payload, _ := json.Marshal(cfg)
	signed, _ := SignedEnvelope(payload, private)
	os.WriteFile(opts.ConfigPath, signed, 0600)
	opts.TrustedKey = hex.EncodeToString(private.Public().(ed25519.PublicKey))
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal("initial:", err)
	}
	var first activeRecord
	raw, _ := os.ReadFile(filepath.Join(opts.Root, "launcher", "active-1.json"))
	json.Unmarshal(raw, &first)
	// The new game manifest still passes our fake Runtime 'verify', but specifies
	// an unsupported Java policy. This forces a failure AFTER component commit.
	parts["profile-manifest.json"] = []byte(`{"projectId":"hello","profileId":"vanilla","channel":"stable","runtime":{"java":{"majorVersion":999,"distribution":"temurin"},"launch":{"offlineMode":true}}}`)
	cfg.Manifest = fakeArtifact(parts["profile-manifest.json"], cfg.Manifest.URL)
	payload, _ = json.Marshal(cfg)
	signed, _ = SignedEnvelope(payload, private)
	os.WriteFile(opts.ConfigPath, signed, 0600)
	os.WriteFile(filepath.Join(opts.OfflineDir, "profile-manifest.json"), parts["profile-manifest.json"], 0600)
	if err := Run(context.Background(), opts); err == nil {
		t.Fatal("invalid Java policy accepted")
	}
	// Prior signed runtime and pointer must be restored with monotonically
	// increasing commit generation; the failed one remains available for diagnosis.
	records := []activeRecord{}
	for _, slot := range []string{"active-0.json", "active-1.json"} {
		raw, err := os.ReadFile(filepath.Join(opts.Root, "launcher", slot))
		if err != nil {
			continue
		}
		var r activeRecord
		json.Unmarshal(raw, &r)
		records = append(records, r)
	}
	var latest activeRecord
	for _, r := range records {
		if r.Generation > latest.Generation {
			latest = r
		}
	}
	if latest.Digest != first.Digest || latest.Generation < 3 {
		t.Fatalf("rollback failed, records=%+v", records)
	}
}
func TestRecoveryRemovesUncommittedStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper test")
	}
	root := t.TempDir()
	opts, _ := makeOfflineFixture(t, root, baseParts())
	releaseRoot := filepath.Join(opts.Root, "launcher", "releases", ".incomplete-from-power-loss")
	if err := os.MkdirAll(releaseRoot, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(releaseRoot, "truncated-java.bin"), []byte("halfwritten"), 0600)
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(releaseRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphaned staging directory not recovered", err)
	}
}
