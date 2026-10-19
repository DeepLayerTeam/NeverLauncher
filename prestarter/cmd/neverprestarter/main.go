package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/DeepLayerTeam/NeverLauncher/prestarter"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

// Replaced at compile time using -ldflags -X. An empty embedded trust key
// deliberately prevents production bootstrap until a trust root is provisioned.
var embeddedRootPublicKey string
var version = "0.23.8"

func main() {
	var opts prestarter.Options
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	defaultConfig := filepath.Join(filepath.Dir(exe), "bootstrap.signed.json")
	defaultRoot, e := applicationRoot()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	flag.StringVar(&opts.ConfigPath, "config", defaultConfig, "path to local signed bootstrap configuration")
	flag.StringVar(&opts.Root, "root", defaultRoot, "absolute application data directory")
	flag.StringVar(&opts.OfflineDir, "offline-dir", "", "optional local verified archive bundle")
	flag.BoolVar(&opts.Offline, "offline", false, "prohibit network access")
	flag.BoolVar(&opts.LaunchProfile, "launch-profile", false, "launch a signed offline-mode Minecraft profile")
	flag.StringVar(&opts.Username, "username", "", "offline Minecraft username (requires --launch-profile)")
	flag.BoolVar(&opts.NoDesktop, "no-desktop", false, "stage, recover and install only")
	var operatorKey string
	flag.StringVar(&operatorKey, "operator-root-public-key", "", "explicit locally provisioned trust root for operator builds (cannot override an embedded key)")
	flag.Parse()
	opts.TrustedKey = embeddedRootPublicKey
	if opts.TrustedKey == "" {
		opts.TrustedKey = operatorKey
	} else if operatorKey != "" && operatorKey != embeddedRootPublicKey {
		fmt.Fprintln(os.Stderr, "operator key conflicts with embedded root")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := prestarter.Run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "neverprestarter "+version+": "+err.Error())
		os.Exit(1)
	}
	fmt.Println("NeverLauncher bootstrap complete")
}

func applicationRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(base) {
			return filepath.Join(base, "NeverLauncher"), nil
		}
		return filepath.Join(home, "AppData", "Local", "NeverLauncher"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "NeverLauncher"), nil
	default:
		if base := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(base) {
			return filepath.Join(base, "NeverLauncher"), nil
		}
		return filepath.Join(home, ".local", "share", "NeverLauncher"), nil
	}
}
