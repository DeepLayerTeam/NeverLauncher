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
		t.Fatalf("допустимый запуск отклонён: %v", err)
	}
	if err := guardCompatValidateLaunch0502(root, "other", p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("Принят неверный проект")
	}
	intruder := artifact0502(t, root, "mod", "mods/injected.jar", "unlisted mod")
	if err := launch(); err == nil || !strings.Contains(err.Error(), "не разрешён политикой совместимости Guard") {
		t.Fatalf("принят неизвестный мод: %v", err)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(intruder.Path))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods/fabric-api.jar"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "Несовпадение: хеш совместимости Guard") {
		t.Fatalf("принят изменённый мод: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods/fabric-api.jar"), []byte("real jar bytes fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	p.Epoch = 2
	p.RevokedDigests = []string{agent.SHA256}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "отозван") {
		t.Fatalf("принят отозванный агент: %v", err)
	}
	p.RevokedDigests = nil
	p.RevokedTransforms = []string{"net.minecraft.client.Minecraft"}
	p.Epoch = 3
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if err := launch(); err == nil || !strings.Contains(err.Error(), "Преобразование совместимости Guard отозвано") {
		t.Fatalf("принята отозванная трансформация: %v", err)
	}
	// Старая подписанная политика не может отменить отзыв.
	p.Epoch = 1
	p.RevokedTransforms = nil
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("принят откат к подписанной, но недопустимой версии")
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
	p.Loader = "forge" // при одинаковой эпохе установка другого содержимого запрещена
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("приняты противоречивые подписанные данные")
	}
	if err := os.WriteFile(filepath.Join(root, ".launcher/guard/compatibility.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatValidateLaunch0502(root, "pinned-install-digest", "1.20.1", "fabric", nil, nil); err == nil {
		t.Fatal("принята подмена данных")
	}
	p.Epoch = 2
	p.ExpiresAt = time.Now().Unix() - 1
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("принята подпись с истёкшим сроком действия")
	}
	p.ExpiresAt = time.Now().Unix() + 3600
	p.Artifacts = []guardCompatArtifact0502{{Kind: "mod", Path: "../outside.jar", SHA256: strings.Repeat("0", 64)}}
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err == nil {
		t.Fatal("Небезопасный путь ошибочно принят")
	}
	if err := os.Remove(filepath.Join(root, ".launcher/guard/compatibility.json")); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatValidateLaunch0502(root, "pinned-install-digest", "1.20.1", "fabric", nil, nil); err == nil {
		t.Fatal("принято отсутствие ранее установленной политики")
	}
}
func TestGuardCompatibility0502ExternalRootAndRequired(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("принят пропуск обязательной политики")
	}
	file := signCompat0502(t, p, priv)
	raw, _ := os.ReadFile(file)
	var env guardCompatEnvelope0502
	_ = json.Unmarshal(raw, &env)
	env.Signature = strings.Repeat("0", 128)
	raw, _ = json.Marshal(env)
	_ = os.WriteFile(file, raw, 0600)
	if err := guardCompatInstall0502(root, file, key); err == nil {
		t.Fatal("Принята недействительная подпись")
	}
	embedded := filepath.Join(root, "root.pub")
	raw, _ = os.ReadFile(key)
	_ = os.WriteFile(embedded, raw, 0600)
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), embedded); err == nil {
		t.Fatal("принят корневой каталог, управляемый клиентом")
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
		t.Skipf("символические ссылки недоступны: %v", err)
	}
	if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, nil, nil); err == nil {
		t.Fatal("приняты данные через символическую ссылку")
	}
}

// Интеграция: НАСТОЯЩИЙ Java-агент должен принудительно соблюдать подписанный список
// преобразований для каждого плагина, а не просто проверять объявления JSON в CLI.
func TestGuardCompatibility0502RealJVMPremainClassEnforcement(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("JDK недоступен")
	}
	root, key, priv := compatFixture0502(t)
	example := filepath.Join("..", "..", "..", "examples", "extensions", "trusted-jvm")
	build := exec.Command("sh", "build.sh")
	build.Dir = example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("сборка доверенного агента завершилась ошибкой: %v %s", err, out)
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
	// Фактически установленный мод входит в ту же подписанную область
	// запуска. При появлении другого мода процесс Java не создаётся.
	approvedMod := artifact0502(t, root, "mod", "mods/approved.jar", "fixture-mod-0503")
	p.Artifacts = append(p.Artifacts, approvedMod)
	p.Artifacts = append(p.Artifacts, artifact0502(t, root, "loader-library", "libraries/fabric-loader.jar", "fixture-loader-0504"))
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
		var plugins []string
		for _, item := range record.Plugins {
			plugins = append(plugins, filepath.Join(root, filepath.FromSlash(trustedRoot0306+"/releases/"+record.PackageSHA256+"/plugins/"+item.Name)))
		}
		agentPath := filepath.Join(root, filepath.FromSlash(trustedRoot0306+"/releases/"+record.PackageSHA256+"/agent.jar"))
		if err := guardCompatValidateLaunch0502(root, p.ProjectID, p.Minecraft, p.Loader, []string{agentPath}, plugins); err != nil {
			return "", err
		}
		args := append([]string{"-Dlauncher.trusted.test.transform=true", "-Dlauncher.trusted.game.log=" + filepath.Join(t.TempDir(), "game.log")}, flags...)
		args = append(args, "-cp", filepath.Join(example, "build", "game.jar"), main, "hello world", "arg2")
		cmd := exec.Command("java", args...)
		var output []byte
		output, err = cmd.CombinedOutput()
		return string(output), err
	}
	if output, err := run(); err != nil {
		t.Fatalf("сбой запуска JVM с разрешённым модом и агентом: %v %s", err, output)
	}
	intruder := filepath.Join(root, "mods", "unknown.jar")
	if err := os.WriteFile(intruder, []byte("unapproved"), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err == nil || !strings.Contains(err.Error(), "не разрешён политикой совместимости Guard") {
		t.Fatalf("неизвестный мод дошёл до запуска Java: %v %s", err, output)
	}
	if err := os.Remove(intruder); err != nil {
		t.Fatal(err)
	}
	// Обновление до равноправно действительной подписанной политики, которая не разрешает НИКАКИХ преобразований.
	p.Epoch = 2
	p.Transformations = nil
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err == nil || !strings.Contains(output, "unauthorized class transformation") {
		t.Fatalf("несанкционированное изменение класса во время работы не было заблокировано: %v %s", err, output)
	}
}
