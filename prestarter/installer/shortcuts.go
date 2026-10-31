package installer

import (
	"fmt"
	prestarter "github.com/DeepLayerTeam/Launcher/prestarter"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (i *installation) shortcutPath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if !filepath.IsAbs(appdata) {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Launcher.lnk")
	case "linux":
		base := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(base) {
			base = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(base, "applications", "launcher.desktop")
	default:
		return "" // macOS has an app bundle installed by pkgbuild.
	}
}
func (i *installation) createShortcut(r record, cfg prestarter.Config) error {
	path := i.shortcutPath()
	if path == "" {
		return nil
	}
	if e := secureDir(filepath.Dir(path)); e != nil {
		return e
	}
	base := filepath.Join(i.base, "releases", r.Release)
	name := "Launcher"
	if cfg.Branding != nil {
		name = cfg.Branding.DisplayName
	}
	var contents string
	if runtime.GOOS == "windows" {
		return writeWindowsShortcut(path, filepath.Join(base, binaryName()), filepath.Join(base, "bootstrap.signed.json"), i.root)
	} else {
		// Double-quotes, newlines and backslashes cannot be injected by the signed display name.
		name = strings.NewReplacer("\n", " ", "\r", " ", "\\", " ", "\"", " ").Replace(name)
		contents = fmt.Sprintf("[Desktop Entry]\nType=Application\nName=%s\nExec=\"%s\" --config \"%s\" --root \"%s\"\nTerminal=false\nCategories=Game;\n", name, filepath.Join(base, binaryName()), filepath.Join(base, "bootstrap.signed.json"), i.root)
	}
	return atomicWrite(path, []byte(contents))
}
func (i *installation) removeShortcut() error {
	path := i.shortcutPath()
	if path == "" {
		return nil
	}
	if runtime.GOOS == "windows" {
		return removeWindowsShortcut(path, i.base)
	}
	b, e := regular(path, 32768)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	// Never remove a user-owned shortcut that no longer points to our root.
	if !strings.Contains(string(b), i.base) && !strings.Contains(string(b), filepath.ToSlash(i.base)) {
		return nil
	}
	return os.Remove(path)
}
