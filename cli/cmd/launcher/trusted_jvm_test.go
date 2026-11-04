package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTrustedJVM0306SignedLifecycleAndRealMinecraftHooks(t *testing.T) {
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("JDK unavailable")
	}
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac unavailable")
	}
	repo := filepath.Join("..", "..", "..")
	example := filepath.Join(repo, "examples", "extensions", "trusted-jvm")
	build := exec.Command("sh", "build.sh")
	build.Dir = example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trusted JVM agent: %v\n%s", err, out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	privateKey := filepath.Join(keys, "private.key")
	publicKey := filepath.Join(keys, "public.key")
	if err = os.WriteFile(privateKey, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(publicKey, []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(t.TempDir(), "trusted.nlext")
	source := filepath.Join(example, "build", "package")
	if _, err = packExtensionPackage0202(source, packagePath); err != nil {
		t.Fatal(err)
	}
	if _, err = trustedInstall0306(t.TempDir(), packagePath, publicKey); err == nil {
		t.Fatal("unsigned trusted package accepted")
	}
	if _, err = signExtensionPackage0202(packagePath, packagePath, privateKey, false); err != nil {
		t.Fatal(err)
	}
	root := compatFixture0279(t)
	if err := handleTrustedJVM0306([]string{"trusted-install", "--client-dir", root, "--package", packagePath, "--public-key", publicKey}); err == nil {
		t.Fatal("missing full JVM approval accepted")
	}
	if _, err = trustedInstall0306(root, packagePath, publicKey); err != nil {
		t.Fatal(err)
	}
	insideKey := filepath.Join(root, ".launcher", "mutable-anchor.key")
	if err := os.WriteFile(insideKey, []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = trustedInstall0306(root, packagePath, insideKey); err == nil {
		t.Fatal("client-controlled trust key accepted")
	}

	t.Setenv(trustedPublicKeyEnv0306, publicKey)
	jvm, main, cleanup, err := trustedPrepare0306(root, "example.FixtureGame")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(jvm) != 1 || !strings.HasPrefix(jvm[0], "-javaagent:") || main != "ru.launcher.trusted.MinecraftMain" {
		t.Fatalf("invalid launch: %v %s", jvm, main)
	}
	marker := filepath.Join(t.TempDir(), "hooks.log")
	game := filepath.Join(t.TempDir(), "game.log")
	classpath := filepath.Join(example, "build", "game.jar")
	commandArgs := append([]string{"-Dlauncher.trusted.test.log=" + marker, "-Dlauncher.trusted.game.log=" + game}, jvm...)
	commandArgs = append(commandArgs, "-cp", classpath, main, "hello world", "arg2")
	command := exec.Command("java", commandArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual agent JVM failed: %v: %s", err, output)
	}
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(b)
	for _, s := range []string{"agent-ready:", "before:example.FixtureGame:2", "transform:net.minecraft.client.Minecraft", "after:ok"} {
		if !strings.Contains(logged, s) {
			t.Fatalf("missing %s from hooks: %s", s, logged)
		}
	}
	if actual, err := os.ReadFile(game); err != nil || string(actual) != "game-started" {
		t.Fatalf("Minecraft main never ran: %q %v", actual, err)
	}
	// The actual legacy launcher must append the signed agent without treating
	// user-supplied JVM flags as permission to inject arbitrary agents.
	if runtime.GOOS != "windows" {
		capture := filepath.Join(t.TempDir(), "launch-args.txt")
		launcher := filepath.Join(t.TempDir(), "java8")
		script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'openjdk version \"1.8.0_442\"' >&2; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$TRUSTED_TEST_CAPTURE\"\n"
		if err := os.WriteFile(launcher, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TRUSTED_TEST_CAPTURE", capture)
		if err := runLegacyClient0278(context.Background(), root, launcher, "TestUser", "test-uuid"); err != nil {
			t.Fatal(err)
		}
		argv, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(argv), "-javaagent:") || !strings.Contains(string(argv), "ru.launcher.trusted.MinecraftMain") {
			t.Fatalf("legacy launcher did not execute trusted integration: %s", argv)
		}
	}

	// Exception propagation still invokes the after-main hook, then the JVM fails.
	failArgs := append([]string{}, commandArgs...)
	failArgs[len(failArgs)-1] = "fail"
	failureRun := exec.Command("java", failArgs...)
	if out, err := failureRun.CombinedOutput(); err == nil {
		t.Fatalf("Minecraft failure suppressed: %s", out)
	}
	afterCrash, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterCrash), "after:failed") {
		t.Fatalf("crash hook not called: %s", afterCrash)
	}
	rec, release, err := trustedLoad0306(root, publicKey)
	if err != nil || rec == nil {
		t.Fatalf("verify: %v", err)
	}
	plugin, err := trustedPath0306(root, release+"/plugins/logging-hook.jar")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(plugin, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = trustedPrepare0306(root, "example.FixtureGame"); err == nil {
		t.Fatal("tampered plugin accepted")
	}
	if _, err = trustedInstall0306(root, packagePath, publicKey); err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(publicKey, []byte(hex.EncodeToString(otherPub)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = trustedPrepare0306(root, "example.FixtureGame"); err == nil {
		t.Fatal("wrong trust anchor accepted")
	}
	t.Setenv(trustedPublicKeyEnv0306, "")
	if _, _, _, err = trustedPrepare0306(root, "example.FixtureGame"); err == nil {
		t.Fatal("no external trust anchor accepted")
	}
}

func TestTrustedJVM0306AbsentIsNonIntrusive(t *testing.T) {
	t.Setenv(trustedPublicKeyEnv0306, "")
	args, main, done, err := trustedPrepare0306(t.TempDir(), "example.Game")
	if err != nil {
		t.Fatal(err)
	}
	done()
	if len(args) > 0 || main != "example.Game" {
		t.Fatalf("unexpected activation: %v %s", args, main)
	}
}
