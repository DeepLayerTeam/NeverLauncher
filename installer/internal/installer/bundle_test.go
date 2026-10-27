package installer

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, name, stringValue string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, []byte(stringValue), perm); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(src, "app"), "executable", 0700)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(dir, "public")
	private := filepath.Join(dir, "private")
	put(t, public, hex.EncodeToString(pub), 0600)
	put(t, private, hex.EncodeToString(priv.Seed()), 0600)
	bundle := filepath.Join(dir, "release.zip")
	if err := Pack(src, "0.32.9", private, bundle); err != nil {
		t.Fatal(err)
	}
	return dir, bundle, public, private
}
func TestSignedBundleInstallAndTamper(t *testing.T) {
	dir, bundle, pub, _ := fixture(t)
	v, err := Verify(bundle, pub)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "installed")
	if err := v.Install(dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "app"))
	if err != nil || string(data) != "executable" {
		t.Fatalf("bad install %s %v", data, err)
	}
	if stat, err := os.Stat(filepath.Join(dest, "app")); err != nil || stat.Mode().Perm() != 0755 {
		t.Fatalf("bad permissions %v %v", stat, err)
	}
	if err := v.Install(dest); err == nil {
		t.Fatal("existing installation overwritten")
	}
	// Alter a payload, preserve the original signed manifest. Must fail SHA-256 check.
	z, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(dir, "tampered.zip")
	out, err := os.Create(tampered)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(out)
	for _, entry := range z.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == "payload/app" {
			contents = []byte("changed")
		}
		fh := &zip.FileHeader{Name: entry.Name, Method: zip.Store}
		fh.SetMode(0600)
		w, err := writer.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	writer.Close()
	out.Close()
	z.Close()
	if _, err := Verify(tampered, pub); err == nil {
		t.Fatal("tampering accepted")
	}
}
func TestManifestUnsignedEntryAndBadTrustRoot(t *testing.T) {
	dir, bundle, pub, _ := fixture(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey := filepath.Join(dir, "other.key")
	put(t, otherKey, hex.EncodeToString(otherPub), 0600)
	if _, err := Verify(bundle, otherKey); err == nil {
		t.Fatal("wrong trust key accepted")
	}
	z, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.zip")
	file, err := os.Create(extra)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(file)
	for _, item := range z.File {
		r, _ := item.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		h := &zip.FileHeader{Name: item.Name}
		h.SetMode(0600)
		entry, _ := w.CreateHeader(h)
		entry.Write(b)
	}
	h := &zip.FileHeader{Name: "payload/malicious"}
	h.SetMode(0600)
	entry, _ := w.CreateHeader(h)
	entry.Write([]byte("bad"))
	w.Close()
	file.Close()
	z.Close()
	if _, err := Verify(extra, pub); err == nil {
		t.Fatal("unsigned extra entry accepted")
	}
}
func TestInitSecretsAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "service.env")
	if err := Init(dest, "https://launcher.example", "postgres://nl:secret@localhost/db?sslmode=require", filepath.Join(dir, "storage")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("secret permissions %v %v", st, err)
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("NEVERLAUNCHER_BOOTSTRAP_TOKEN=")) || !bytes.Contains(b, []byte("NEVERLAUNCHER_ENV=production")) {
		t.Fatal("configuration fields missing")
	}
	if err := Init(dest, "https://launcher.example", "postgres://localhost/db", filepath.Join(dir, "storage")); err == nil {
		t.Fatal("init overwrote existing credentials")
	}
	if err := Init(filepath.Join(dir, "bad.env"), "http://evil.example", "postgres://localhost/db", filepath.Join(dir, "storage")); err == nil {
		t.Fatal("allowed insecure non-loopback HTTP")
	}
	if err := Init(filepath.Join(dir, "newline.env"), "https://launcher.example", "postgres://host/db\nINJECTED=true", filepath.Join(dir, "storage")); err == nil {
		t.Fatal("accepted env injection")
	}
}
func TestOwnerBootstrapUsesFilesAndSingleRequest(t *testing.T) {
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	token := filepath.Join(dir, "token")
	put(t, pass, "strong-password-at-least-12", 0600)
	put(t, token, strings.Repeat("a", 64), 0600)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/v1/install/bootstrap-admin" || r.Header.Get("X-NeverLauncher-Bootstrap-Token") != strings.Repeat("a", 64) {
			t.Error("wrong bootstrap request")
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"data":{"status":"admin-created"}}`))
	}))
	defer srv.Close()
	if err := BootstrapOwner(srv.URL, "owner@example.com", "Owner", pass, token); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected one atomic bootstrap call, got %d", calls)
	}
	os.Chmod(pass, 0644)
	if err := BootstrapOwner(srv.URL, "owner@example.com", "Owner", pass, token); err == nil {
		t.Fatal("insecure password file accepted")
	}
}

func TestConcurrentAtomicInstall(t *testing.T) {
	dir, bundle, pub, _ := fixture(t)
	v, err := Verify(bundle, pub)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "installation")
	result := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { result <- v.Install(target) }()
	}
	var successes int
	for i := 0; i < 2; i++ {
		if err := <-result; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one installer to win, got %d", successes)
	}
	b, err := os.ReadFile(filepath.Join(target, "app"))
	if err != nil || string(b) != "executable" {
		t.Fatalf("partially published install: %v", err)
	}
}
func TestBootstrapFromGeneratedEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "service.env")
	if err := Init(envFile, "https://example.test", "postgres://localhost/db", filepath.Join(dir, "storage")); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.HasPrefix(line, "NEVERLAUNCHER_BOOTSTRAP_TOKEN=") {
			token = strings.TrimPrefix(line, "NEVERLAUNCHER_BOOTSTRAP_TOKEN=")
		}
	}
	if len(token) != 64 {
		t.Fatalf("invalid bootstrap token length: %d", len(token))
	}
	pass := filepath.Join(dir, "password")
	put(t, pass, "correct horse battery staple", 0600)
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Header.Get("X-NeverLauncher-Bootstrap-Token") != token {
			t.Error("wrong token")
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	if err := BootstrapOwnerFromEnv(srv.URL, "owner@example.com", "Owner", pass, envFile); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("incorrect bootstrap request count")
	}
	os.Chmod(envFile, 0644)
	if err := BootstrapOwnerFromEnv(srv.URL, "owner@example.com", "Owner", pass, envFile); err == nil {
		t.Fatal("accepted world-readable bootstrap token")
	}
}

func TestSystemdUnitHardening(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "neverlauncher-api")
	secret := filepath.Join(dir, "backend.env")
	unit := filepath.Join(dir, "neverlauncher.service")
	put(t, app, "#!/bin/sh\n", 0755)
	put(t, secret, "BOOTSTRAP=secret\n", 0600)
	if err := WriteSystemdUnit(unit, app, secret); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"User=neverlauncher", "ProtectSystem=strict", "NoNewPrivileges=true", "StateDirectoryMode=0700"} {
		if !bytes.Contains(data, []byte(needle)) {
			t.Fatalf("missing %s", needle)
		}
	}
	if err := WriteSystemdUnit(unit, app, secret); err == nil {
		t.Fatal("overwrote existing service")
	}
	os.Chmod(secret, 0644)
	if err := WriteSystemdUnit(filepath.Join(dir, "bad.service"), app, secret); err == nil {
		t.Fatal("insecure environment accepted")
	}
}
