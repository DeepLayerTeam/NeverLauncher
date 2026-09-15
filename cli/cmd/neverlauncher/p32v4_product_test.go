package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientLifecycleInstallRepairCleanupRollback(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	storage := filepath.Join(root, "storage")
	client := filepath.Join(root, "client")
	dist := filepath.Join(root, "dist")
	mustWrite := func(path, value string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(source, "mods", "core.jar"), "v1-core")
	mustWrite(filepath.Join(source, "libraries", "lib.jar"), "v1-lib")
	mustWrite(filepath.Join(source, "natives", "launch.sh"), "#!/bin/sh\necho launch\n")
	if err := os.Chmod(filepath.Join(source, "natives", "launch.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	pkg1, err := buildClientPackage(source, "demo-project", "vanilla", "stable", "1.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	pkg1Path := filepath.Join(dist, "1.0.0", "client-package.json")
	if err := writeJSONFile(pkg1Path, pkg1); err != nil {
		t.Fatal(err)
	}
	if _, err := clientPackageUpload(pkg1Path, source, storage, "clients/demo-project/vanilla/stable/1.0.0"); err != nil {
		t.Fatal(err)
	}
	installed, err := clientInstallOrUpdate(pkg1Path, storage, client, "install")
	if err != nil {
		t.Fatal(err)
	}
	if installed["status"] != "applied-and-verified" {
		t.Fatalf("install=%v", installed)
	}
	if info, err := os.Stat(filepath.Join(client, "natives", "launch.sh")); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("executable bit not preserved: mode=%v err=%v", func() os.FileMode {
			if info != nil {
				return info.Mode()
			}
			return 0
		}(), err)
	}
	verify, err := verifyClientInstallation(pkg1Path, client)
	if err != nil || !verify.Valid {
		t.Fatalf("verify=%+v err=%v", verify, err)
	}

	mustWrite(filepath.Join(client, "mods", "core.jar"), "corrupt")
	verify, err = verifyClientInstallation(pkg1Path, client)
	if err != nil || verify.Valid || len(verify.Corrupted) != 1 {
		t.Fatalf("corruption not detected: %+v err=%v", verify, err)
	}
	if _, err := repairClientInstallation(pkg1Path, storage, client, false); err != nil {
		t.Fatal(err)
	}
	verify, _ = verifyClientInstallation(pkg1Path, client)
	if !verify.Valid {
		t.Fatalf("repair failed: %+v", verify)
	}

	mustWrite(filepath.Join(client, "mods", "orphan.jar"), "orphan")
	verify, _ = verifyClientInstallation(pkg1Path, client)
	if len(verify.Orphans) != 1 {
		t.Fatalf("orphan not detected: %+v", verify)
	}
	clean, err := cleanupClientInstallation(pkg1Path, client)
	if err != nil {
		t.Fatal(err)
	}
	if clean["status"] != "quarantined" {
		t.Fatalf("cleanup=%v", clean)
	}
	if _, err := os.Stat(filepath.Join(client, "mods", "orphan.jar")); !os.IsNotExist(err) {
		t.Fatalf("orphan still exists: %v", err)
	}

	mustWrite(filepath.Join(source, "mods", "core.jar"), "v2-core")
	pkg2, err := buildClientPackage(source, "demo-project", "vanilla", "stable", "2.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	pkg2Path := filepath.Join(dist, "2.0.0", "client-package.json")
	if err := writeJSONFile(pkg2Path, pkg2); err != nil {
		t.Fatal(err)
	}
	if _, err := clientPackageUpload(pkg2Path, source, storage, "clients/demo-project/vanilla/stable/2.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := clientInstallOrUpdate(pkg2Path, storage, client, "update"); err != nil {
		t.Fatal(err)
	}
	beforeRollback, _, _ := hashFile(filepath.Join(client, "mods", "core.jar"))
	v1, _, _ := hashFile(filepath.Join(storage, "clients", "demo-project", "vanilla", "stable", "1.0.0", "mods", "core.jar"))
	if beforeRollback == v1 {
		t.Fatal("update did not change client")
	}
	if _, err := rollbackClientInstallation(client, "previous"); err != nil {
		t.Fatal(err)
	}
	afterRollback, _, err := hashFile(filepath.Join(client, "mods", "core.jar"))
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback != v1 {
		t.Fatalf("rollback checksum=%s want=%s", afterRollback, v1)
	}
	verify, err = verifyClientInstallation(pkg1Path, client)
	if err != nil || !verify.Valid {
		t.Fatalf("rollback verify=%+v err=%v", verify, err)
	}
}

func TestDesktopPackageRequiresRealArtifactAndDetectsTampering(t *testing.T) {
	artifactDir := t.TempDir()
	out := t.TempDir()
	artifact := filepath.Join(artifactDir, "neverlauncher-desktop-linux-amd64")
	if err := os.WriteFile(artifact, []byte("real-native-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := buildDesktopPackage(version, artifactDir, out, "linux"); err != nil {
		t.Fatal(err)
	}
	if err := verifyDesktopPackage(out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "neverlauncher-desktop-linux-amd64"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyDesktopPackage(out); err == nil {
		t.Fatal("tampered desktop package accepted")
	}
}

func TestStandaloneFirstRunUsesPinnedImagesWithoutBuildContext(t *testing.T) {
	out := t.TempDir()
	digest := strings.Repeat("a", 64)
	files, err := writeFirstRunBundle(out, "https://launcher.example", "demo-project", "vanilla", "registry.example/api@sha256:"+digest, "registry.example/admin@sha256:"+digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 7 {
		t.Fatalf("files=%v", files)
	}
	raw, err := os.ReadFile(filepath.Join(out, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "context: ../..") || strings.Contains(text, "dockerfile: services/api") || strings.Contains(text, "dockerfile: apps/admin") {
		t.Fatalf("standalone compose contains source build context:\n%s", text)
	}
	if !strings.Contains(text, "image: registry.example/api@sha256:"+digest) || !strings.Contains(text, "image: registry.example/admin@sha256:"+digest) {
		t.Fatalf("pinned images missing:\n%s", text)
	}
}

func TestKeyRotationAttestationAndRevocation(t *testing.T) {
	dir := t.TempDir()
	payload, err := rotateSecurityKey([]string{"rotate-key", "--registry-dir", dir, "--key", "release-signing"})
	if err != nil {
		t.Fatal(err)
	}
	key := payload["key"].(securityKeyRecord)
	privatePath := payload["privateKeyFile"].(string)
	artifact := filepath.Join(t.TempDir(), "PROVENANCE.json")
	if err := os.WriteFile(artifact, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	att, err := securityAttest([]string{"attest", "--path", artifact, "--private-key", privatePath})
	if err != nil {
		t.Fatal(err)
	}
	pubPath := key.PublicKeyFile
	if _, err := verifyDetachedEd25519(artifact, att["signature"].(string), pubPath); err != nil {
		t.Fatal(err)
	}
	if err := ensurePublicKeyNotRevoked(dir, pubPath); err != nil {
		t.Fatal(err)
	}
	if _, err := securityRevocations([]string{"revocation-list", "--registry-dir", dir, "--revoke", key.ID}); err != nil {
		t.Fatal(err)
	}
	if err := ensurePublicKeyNotRevoked(dir, pubPath); err == nil {
		t.Fatal("revoked key accepted")
	}
}

func TestDependencySBOMAndProvenanceUseRealInputs(t *testing.T) {
	sbom, err := dependencySBOM(".", version)
	if err != nil {
		t.Fatal(err)
	}
	packages, ok := sbom["packages"].([]sbomPackage)
	if !ok || len(packages) < 20 {
		t.Fatalf("dependency SBOM too small: %T %d", sbom["packages"], len(packages))
	}
	artifacts := t.TempDir()
	if err := os.WriteFile(filepath.Join(artifacts, "artifact.bin"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	prov, err := slsaProvenance(".", artifacts, version)
	if err != nil {
		t.Fatal(err)
	}
	subjects := prov["subject"].([]map[string]any)
	if len(subjects) != 1 || subjects[0]["name"] != "artifact.bin" {
		t.Fatalf("subjects=%v", subjects)
	}
}
