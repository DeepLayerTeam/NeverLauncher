package main

import (
	"flag"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/installer/internal/installer"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, `neverlauncher-install:
  verify --bundle BUNDLE --trusted-key ED25519_PUBLIC_HEX_FILE
  install --bundle BUNDLE --trusted-key ED25519_PUBLIC_HEX_FILE --target ABSOLUTE_NEW_DIRECTORY
  pack --source FILES --version X.Y.Z --private-key ED25519_SEED_HEX_FILE --output BUNDLE
  init --output /etc/neverlauncher/service.env --public-url https://host --dsn POSTGRES_DSN --storage /var/lib/neverlauncher/storage
  bootstrap-owner --url https://host --email EMAIL --name NAME --password-file 0600_FILE --env-file INSTALL_ENV (or --token-file 0600_FILE)
  systemd-unit --binary /opt/neverlauncher/bin/neverlauncher-api --env-file /etc/neverlauncher/backend.env --output /etc/systemd/system/neverlauncher.service`)
}
func run() error {
	if len(os.Args) < 2 {
		usage()
		return fmt.Errorf("subcommand required")
	}
	switch os.Args[1] {
	case "verify", "install":
		flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
		bundle := flags.String("bundle", "", "signed release archive")
		key := flags.String("trusted-key", "", "independent pinned Ed25519 public key file")
		target := flags.String("target", "", "new absolute installation directory")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		if len(flags.Args()) > 0 {
			return fmt.Errorf("unexpected arguments")
		}
		v, err := installer.Verify(*bundle, *key)
		if err != nil {
			return err
		}
		if os.Args[1] == "install" {
			if err := v.Install(*target); err != nil {
				return err
			}
		}
		fmt.Printf("verified NeverLauncher %s\n", v.Manifest.Version)
		return nil
	case "pack":
		f := flag.NewFlagSet("pack", flag.ContinueOnError)
		source := f.String("source", "", "")
		version := f.String("version", "", "")
		key := f.String("private-key", "", "")
		out := f.String("output", "", "")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		return installer.Pack(*source, *version, *key, *out)
	case "init":
		f := flag.NewFlagSet("init", flag.ContinueOnError)
		out := f.String("output", "", "")
		public := f.String("public-url", "", "")
		dsn := f.String("dsn", "", "")
		store := f.String("storage", "", "")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		return installer.Init(*out, *public, *dsn, *store)
	case "systemd-unit":
		f := flag.NewFlagSet("systemd-unit", flag.ContinueOnError)
		out := f.String("output", "", "")
		binary := f.String("binary", "", "")
		envFile := f.String("env-file", "", "")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		if len(f.Args()) > 0 {
			return fmt.Errorf("unexpected arguments")
		}
		return installer.WriteSystemdUnit(*out, *binary, *envFile)
	case "bootstrap-owner":
		f := flag.NewFlagSet("bootstrap-owner", flag.ContinueOnError)
		url := f.String("url", "", "")
		email := f.String("email", "", "")
		name := f.String("name", "", "")
		pass := f.String("password-file", "", "")
		token := f.String("token-file", "", "")
		envFile := f.String("env-file", "", "")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		if (*token == "") == (*envFile == "") {
			return fmt.Errorf("choose exactly one of --token-file and --env-file")
		}
		if *envFile != "" {
			return installer.BootstrapOwnerFromEnv(*url, *email, *name, *pass, *envFile)
		}
		return installer.BootstrapOwner(*url, *email, *name, *pass, *token)
	default:
		usage()
		return fmt.Errorf("unknown subcommand")
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "neverlauncher-install:", err)
		os.Exit(1)
	}
}
