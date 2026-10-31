package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/DeepLayerTeam/Launcher/prestarter/installer"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

var embeddedRootPublicKey string // filled by linker from release-time provisioned key
var version = "0.23.12"

func rootDir() (string, error) {
	home, e := os.UserHomeDir()
	if e != nil {
		return "", e
	}
	switch runtime.GOOS {
	case "windows":
		if p := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(p) {
			return filepath.Join(p, "Launcher"), nil
		}
		return filepath.Join(home, "AppData", "Local", "Launcher"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Launcher"), nil
	default:
		if p := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(p) {
			return filepath.Join(p, "Launcher"), nil
		}
		return filepath.Join(home, ".local", "share", "Launcher"), nil
	}
}
func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "install")
	}
	root, e := rootDir()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	action := os.Args[1]
	f := flag.NewFlagSet(action, flag.ExitOnError)
	defaultBundle := filepath.Dir(exe)
	if runtime.GOOS == "darwin" {
		defaultBundle = filepath.Clean(filepath.Join(defaultBundle, "..", "Resources", "bundle"))
	}
	opts := installer.Options{Root: root, Bundle: defaultBundle, TrustedKey: embeddedRootPublicKey}
	f.StringVar(&opts.Root, "root", root, "absolute installation root")
	f.StringVar(&opts.Bundle, "bundle", opts.Bundle, "directory containing signed bootstrap and Prestarter")
	f.BoolVar(&opts.Offline, "offline", false, "install using verified offline source only")
	f.BoolVar(&opts.NoStart, "no-start", false, "provision without Desktop start")
	f.Parse(os.Args[2:])
	if (action == "install" || action == "verify") && opts.Bundle == defaultBundle && runtime.GOOS == "windows" {
		unpacked, embeddedOffline, loadErr := unpackEmbedded()
		if loadErr != nil {
			fmt.Fprintln(os.Stderr, loadErr)
			os.Exit(2)
		}
		if unpacked != "" {
			defer os.RemoveAll(unpacked)
			opts.Bundle = unpacked
			opts.Offline = opts.Offline || embeddedOffline
		}
	}

	if opts.TrustedKey == "" {
		fmt.Fprintln(os.Stderr, "unsigned neverinstaller: pinned trust root required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch action {
	case "install":
		e = installer.Install(ctx, opts)
	case "verify":
		_, _, e = installer.VerifyBundle(opts.Bundle, opts.TrustedKey, opts.Offline)
	case "repair":
		e = installer.Repair(ctx, opts)
	case "uninstall":
		e = installer.Uninstall(opts)
	default:
		fmt.Fprintln(os.Stderr, "unknown action")
		os.Exit(2)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "NeverInstaller "+version+": "+e.Error())
		os.Exit(1)
	}
	fmt.Println("NeverInstaller " + version + ": " + action + " complete")
}
