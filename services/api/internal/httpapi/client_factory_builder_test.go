package httpapi

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFactoryBuilderValidation02710(t *testing.T) {
	valid := factoryBuilderRequest02710{Minecraft: "1.21.1", Loader: "fabric", LoaderVersion: "0.16.13", Target: "linux/x86_64"}
	if err := factoryValidateRequest02710(factoryBuilderRequest02710{Minecraft: "1.14.2 Pre-Release 3", Loader: "vanilla", Target: "windows/x86_64"}); err != nil {
		t.Fatalf("Отклонён действительный исторический идентификатор версии Minecraft: %v", err)
	}
	if err := factoryValidateRequest02710(valid); err != nil {
		t.Fatalf("Точный селектор: %v", err)
	}
	for _, input := range []factoryBuilderRequest02710{
		{Minecraft: "latest-release", Loader: "vanilla", Target: "linux/x86_64"},
		{Minecraft: "1.21.1", Loader: "fabric", LoaderVersion: "latest-stable", Target: "linux/x86_64"},
		{Minecraft: "1.21.1", Loader: "fabric", LoaderVersion: "../../a", Target: "linux/x86_64"},
		{Minecraft: "1.21.1", Loader: "forge", LoaderVersion: "1.0", Target: "freebsd/x86_64"},
		{Minecraft: "1.21.1", Loader: "fabric;bash", LoaderVersion: "1.0", Target: "linux/x86_64"},
	} {
		if factoryValidateRequest02710(input) == nil {
			t.Errorf("Принята недопустимая конфигурация: %+v", input)
		}
	}
}
func TestFactoryBuilderPersistenceAndTamper02710(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 32)
	dir, err := factoryJobPath02710(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	job := factoryBuilderJob02710{ID: id, WorkspaceID: "ws-1", ProjectID: "p", OwnerID: "user", State: "completed", CreatedAt: time.Now()}
	if err = factorySave02710(dir, job); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := factoryRead02710(root, id)
	if err != nil || loaded.State != "completed" {
		t.Fatalf("Чтение задания: %+v %v", loaded, err)
	}
	if _, err = factoryJobPath02710(root, "../escape"); err == nil {
		t.Fatal("Разрешён выход за пределы каталога")
	}
	if err = os.WriteFile(filepath.Join(root, "artifact.bin"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = factoryVerifyArtifact02710(root, "artifact.bin", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"); err != nil {
		t.Fatal(err)
	}
	if _, err = factoryVerifyArtifact02710(root, "artifact.bin", strings.Repeat("0", 64)); err == nil {
		t.Fatal("Принят изменённый артефакт")
	}
	if _, err = factoryVerifyArtifact02710(root, "../artifact.bin", ""); err == nil {
		t.Fatal("Разрешён выход за пределы каталога")
	}
}
func TestFactoryBuilderWorkerExecution02710(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	root := t.TempDir()
	id := strings.Repeat("b", 32)
	dir, err := factoryJobPath02710(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Это реальная фикстура подпроцесса для моста, но не запуск Minecraft;
	// настоящий CLI и внешние интеграции проверяются отдельным CI.
	script := filepath.Join(root, "fixture-cli")
	body := `#!/bin/sh
set -eu
mode="$3"
case "$mode" in
build)
 client=""; out=""
 while [ "$#" -gt 0 ]; do
  case "$1" in
   --client-dir) client="$2"; shift 2;;
   --output) out="$2"; shift 2;;
   *) shift;;
  esac
 done
 mkdir -p "$client"
 printf hello > "$client/test.bin"
 cat > "$out" <<'JSON'
{"minecraftVersion":"1.21.1","loader":"vanilla","reproducibilitySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","outputs":[{"path":"test.bin","sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5}]}
JSON
 ;;
verify)
 client=""; out=""
 while [ "$#" -gt 0 ]; do
  case "$1" in
   --client-dir) client="$2"; shift 2;;
   --output) out="$2"; shift 2;;
   *) shift;;
  esac
 done
 test "$(cat "$client/test.bin")" = hello
 printf '{}\n' > "$out"
 ;;
esac
`
	if err = os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	job := factoryBuilderJob02710{ID: id, State: "queued", Request: factoryBuilderRequest02710{Minecraft: "1.21.1", Loader: "vanilla", Target: "linux/x86_64"}}
	factoryRun02710(script, root, job)
	got, _, err := factoryRead02710(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "completed" || got.Files != 1 || got.PlanDigest != strings.Repeat("a", 64) {
		t.Fatalf("Рабочий процесс не выполнил сборку и проверку: %+v", got)
	}
}
