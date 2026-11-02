package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func compatFixture0502(t *testing.T) (string, string, ed25519.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(outside, "root.pub")
	if err = os.WriteFile(key, []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardCompatKeyEnv0502, key)
	t.Setenv(guardCompatRequiredEnv0502, "1")
	return root, key, priv
}
func signCompat0502(t *testing.T, p guardCompatPolicy0502, priv ed25519.PrivateKey) string {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append([]byte(guardCompatDomain0502), data...))
	envelope := guardCompatEnvelope0502{Schema: guardCompatSchema0502, Payload: base64.StdEncoding.EncodeToString(data), Signature: hex.EncodeToString(sig)}
	raw, _ := json.Marshal(envelope)
	file := filepath.Join(t.TempDir(), "policy.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}
func policyFixture0502() guardCompatPolicy0502 {
	now := time.Now().Unix()
	return guardCompatPolicy0502{Schema: guardCompatSchema0502, ProjectID: "pinned-install-digest", Minecraft: "1.20.1", Loader: "fabric", Epoch: 1, IssuedAt: now - 30, ExpiresAt: now + 3600, Artifacts: []guardCompatArtifact0502{}, Transformations: []guardCompatTransform0502{}, RevokedDigests: []string{}, RevokedTransforms: []string{}}
}
func artifact0502(t *testing.T, root, kind, rel, content string) guardCompatArtifact0502 {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(content))
	return guardCompatArtifact0502{Kind: kind, Path: rel, SHA256: hex.EncodeToString(digest[:])}
}
func TestGuardCompatibility0502RealFileEnforcementAndRevocation(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	a := artifact0502(t, root, "mod", "mods/fabric-api.jar", "real jar bytes fixture")
	b := artifact0502(t, root, "native-library", "natives/liblwjgl.so", "native bytes")
	agent := artifact0502(t, root, "java-agent", "extensions/agent.jar", "agent payload")
	plugin := artifact0502(t, root, "java-plugin", "extensions/plugin.jar", "plugin payload")
	p.Artifacts = []guardCompatArtifact0502{a, b, agent, plugin}
	p.Transformations = []guardCompatTransform0502{{ID: "net.minecraft.client.Minecraft", OwnerSHA256: plugin.SHA256}}
	file := signCompat0502(t, p, priv)
	if err := guardCompatInstall0502(root, file, key); err != nil {
		t.Fatal(err)
	}
	launch := func() error {
		return guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, []string{filepath.Join(root, "extensions/agent.jar")}, []string{filepath.Join(root, "extensions/plugin.jar")})
	}
	if err := launch(); err != nil {
		t.Fatalf("valid allowed launch denied: %v", err)
	}
	if err := guardCompatValidateLaunch0502(root, "other", p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("wrong project accepted")
	}
	intruder := artifact0502(t, root, "mod", "mods/injected.jar", "unlisted mod")
	if err := launch(); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("unknown mod accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(intruder.Path))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods/fabric-api.jar"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered mod accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods/fabric-api.jar"), []byte("real jar bytes fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	p.Epoch = 2
	p.RevokedDigests = []string{agent.SHA256}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked agent accepted: %v", err)
	}
	p.RevokedDigests = nil
	p.RevokedTransforms = []string{"net.minecraft.client.Minecraft"}
	p.Epoch = 3
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "transformation revoked") {
		t.Fatalf("revoked transform accepted: %v", err)
	}
	// A signed old policy cannot roll back a revocation.
	p.Epoch = 1
	p.RevokedTransforms = nil
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("signed rollback accepted")
	}
}
func TestGuardCompatibility0502SignatureExpiryEquivocationAndSafety(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	file := signCompat0502(t, p, priv)
	if err := guardCompatInstall0502(root, file, key); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, nil, nil); err != nil {
		t.Fatal(err)
	}
	p.Loader = "forge" // equal epoch, different content must not install
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("equivocation accepted")
	}
	if err := os.WriteFile(filepath.Join(root, ".launcher/guard/compatibility.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatValidateLaunch0502(root, "pinned-install-digest", "1.20.1", "fabric", nil, nil); err == nil {
		t.Fatal("tamper accepted")
	}
	p.Epoch = 2
	p.ExpiresAt = time.Now().Unix() - 1
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("expired signature accepted")
	}
	p.ExpiresAt = time.Now().Unix() + 3600
	p.Artifacts = []guardCompatArtifact0502{{Kind: "mod", Path: "../outside.jar", SHA256: strings.Repeat("0", 64)}}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("unsafe path accepted")
	}
	if err := os.Remove(filepath.Join(root, ".launcher/guard/compatibility.json")); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatValidateLaunch0502(root, "pinned-install-digest", "1.20.1", "fabric", nil, nil); err == nil {
		t.Fatal("missing previously installed policy accepted")
	}
}
func TestGuardCompatibility0502ExternalRootAndRequired(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("required policy omission accepted")
	}
	file := signCompat0502(t, p, priv)
	raw, _ := os.ReadFile(file)
	var env guardCompatEnvelope0502
	_ = json.Unmarshal(raw, &env)
	env.Signature = strings.Repeat("0", 128)
	raw, _ = json.Marshal(env)
	_ = os.WriteFile(file, raw, 0600)
	if err := guardCompatInstall0502(root, file, key); err == nil {
		t.Fatal("invalid signature accepted")
	}
	embedded := filepath.Join(root, "root.pub")
	raw, _ = os.ReadFile(key)
	_ = os.WriteFile(embedded, raw, 0600)
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), embedded); err == nil {
		t.Fatal("client-controlled root accepted")
	}
}
func TestGuardCompatibility0502SymlinkAndUnknownArtifact(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	a := artifact0502(t, root, "mod", "mods/allowed.jar", "approved")
	p.Artifacts = []guardCompatArtifact0502{a}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "mods/allowed.jar"), filepath.Join(root, "mods/alias.jar")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("symlinked payload accepted")
	}
}

// Integration: the *real Java agent* must enforce the signed per-plugin
// transformation list, not just a CLI inspection of JSON declarations.
func TestGuardCompatibility0502RealJVMPremainClassEnforcement(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("JDK unavailable")
	}
	root, key, priv := compatFixture0502(t)
	example := filepath.Join("..", "..", "..", "examples", "extensions", "trusted-jvm")
	build := exec.Command("sh", "build.sh")
	build.Dir = example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trusted agent: %v %s", err, out)
	}
	packagePath := filepath.Join(t.TempDir(), "signed.nlext")
	if _, err := packExtensionPackage0202(filepath.Join(example, "build", "package"), packagePath); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(t.TempDir(), "private.hex")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := signExtensionPackage0202(packagePath, packagePath, privatePath, false); err != nil {
		t.Fatal(err)
	}
	record, err := trustedInstall0306(root, packagePath, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(trustedPublicKeyEnv0306, key)
	p := policyFixture0502()
	p.Artifacts = []guardCompatArtifact0502{
		{Kind: "java-agent", Path: trustedRoot0306 + "/releases/" + record.PackageSHA256 + "/agent.jar", SHA256: record.AgentSHA256},
	}
	for _, plugin := range record.Plugins {
		p.Artifacts = append(p.Artifacts, guardCompatArtifact0502{
			Kind: "java-plugin", Path: trustedRoot0306 + "/releases/" + record.PackageSHA256 + "/plugins/" + plugin.Name, SHA256: plugin.SHA256,
		})
	}
	p.Transformations = []guardCompatTransform0502{{ID: "net.minecraft.client.Minecraft", OwnerSHA256: record.Plugins[0].SHA256}}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	run := func() (string, error) {
		flags, main, cleanup, err := trustedPrepare0306(root, "example.FixtureGame")
		if err != nil {
			return "", err
		}
		defer cleanup()
		args := append([]string{"-Dlauncher.trusted.test.transform=true", "-Dlauncher.trusted.game.log=" + filepath.Join(t.TempDir(), "game.log")}, flags...)
		args = append(args, "-cp", filepath.Join(example, "build", "game.jar"), main, "hello world", "arg2")
		cmd := exec.Command("java", args...)
		var output []byte
		output, err = cmd.CombinedOutput()
		return string(output), err
	}
	if output, err := run(); err != nil {
		t.Fatalf("allowed class transform killed JVM: %v %s", err, output)
	}
	// Upgrade to an equally valid signed policy that authorizes NO transformations.
	p.Epoch = 2
	p.Transformations = nil
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err == nil || !strings.Contains(output, "unauthorized class transformation") {
		t.Fatalf("unauthorized live class transform did not fail closed: %v %s", err, output)
	}
}
