package prestarter

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHeadlessPrestarterDoesNotProvisionDesktop0427(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Имитатор среды выполнения для POSIX")
	}
	opts, _ := makeOfflineFixture(t, t.TempDir(), baseParts())
	opts.NoDesktop = true
	opts.LaunchProfile = true
	opts.Username = "TestPlayer"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, ".launcher-prestarter", "desktop-config")
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("Безголовый режим записал конфигурацию Desktop: %v", err)
	}
}
