package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardLoader0504SignedSourceAndRevocation(t *testing.T) {
	root := t.TempDir()
	library := artifact0502(t, root, "loader-library", "libraries/fabric-loader.jar", "verified loader code")
	p := policyFixture0502()
	p.Artifacts = []guardCompatArtifact0502{library}
	out, err := guardLoaderConfig0504(root, p)
	if err != nil || !strings.Contains(out, "loader.id=fabric\nloader.count=1") || !strings.Contains(out, library.SHA256) {
		t.Fatalf("Подписанный код отклонён: %v %s", err, out)
	}
	p.RevokedDigests = []string{library.SHA256}
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("revoked loader accepted")
	}
	p.RevokedDigests = nil
	if err := os.WriteFile(filepath.Join(root, "libraries", "fabric-loader.jar"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("tampered loader accepted")
	}
}
func TestGuardLoader0504RejectUnboundOrUnsupportedLoaders(t *testing.T) {
	root := t.TempDir()
	p := policyFixture0502()
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("Принят загрузчик Fabric без привязки")
	}
	p.Loader = "neoforge"
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("Принят загрузчик NeoForge без привязки")
	}
	p.Loader = "vanilla"
	if out, err := guardLoaderConfig0504(root, p); err != nil || !strings.Contains(out, "loader.count=0") {
		t.Fatalf("vanilla: %v %s", err, out)
	}
	p.Loader = "custom-loader"
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("Принят неизвестный загрузчик")
	}
}
func TestGuardLoader0504RejectSymlinkAndNonJAR(t *testing.T) {
	root := t.TempDir()
	p := policyFixture0502()
	p.Artifacts = []guardCompatArtifact0502{artifact0502(t, root, "loader-library", "libraries/not-a-jar.txt", "fake")}
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("Принят загрузчик, не являющийся JAR-файлом")
	}
	a := artifact0502(t, root, "loader-library", "libraries/real.jar", "real")
	p.Artifacts = []guardCompatArtifact0502{{Kind: "loader-library", Path: "libraries/link.jar", SHA256: a.SHA256}}
	if err := os.Symlink("real.jar", filepath.Join(root, "libraries", "link.jar")); err != nil {
		t.Skipf("символическая ссылка недоступна: %v", err)
	}
	if _, err := guardLoaderConfig0504(root, p); err == nil {
		t.Fatal("symlinked loader accepted")
	}
}

func TestGuardLoader0504SignedClassHashBindings(t *testing.T) {
	root, key, private := compatFixture0502(t)
	p := policyFixture0502()
	lib := artifact0502(t, root, "loader-library", "libraries/fabric-loader.jar", "loader")
	p.Artifacts = []guardCompatArtifact0502{lib}
	p.LoaderClassBytes = []guardCompatClassBytes0504{{Class: "net.minecraft.client.Minecraft", SHA256: strings.Repeat("a", 64)}}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, private), key); err != nil {
		t.Fatal(err)
	}
	v, err := guardCompatLoad0502(root, key)
	if err != nil || v == nil {
		t.Fatalf("signed class hashes not loaded: %v", err)
	}
	props, err := guardLoaderConfig0504(root, v.Policy)
	if err != nil || !strings.Contains(props, "loader.class.count=1") || !strings.Contains(props, "loader.class.0.sha256="+strings.Repeat("a", 64)) {
		t.Fatalf("signed class digest not forwarded: %v %s", err, props)
	}
	p.Epoch++
	p.LoaderClassBytes = append(p.LoaderClassBytes, p.LoaderClassBytes[0])
	if err := guardCompatInstall0502(root, signCompat0502(t, p, private), key); err == nil {
		t.Fatal("duplicate signed class mapping accepted")
	}
	p.LoaderClassBytes[1].Class = "invalid class name"
	if err := guardCompatInstall0502(root, signCompat0502(t, p, private), key); err == nil {
		t.Fatal("invalid signed class name accepted")
	}
	p.LoaderClassBytes = p.LoaderClassBytes[:1]
	p.LoaderClassBytes[0].SHA256 = "not-sha256"
	if err := guardCompatInstall0502(root, signCompat0502(t, p, private), key); err == nil {
		t.Fatal("invalid class hash accepted")
	}
}
