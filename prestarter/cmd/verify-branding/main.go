// verify-branding independently checks an owner-signed bootstrap with the
// production Prestarter Ed25519 verifier. It prints no private key material.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DeepLayerTeam/Launcher/prestarter"
)

func run() error {
	config := flag.String("config", "", "path to bootstrap.signed.json")
	rootFile := flag.String("root-key-file", "", "path to provisioned public Ed25519 root (hex)")
	policyFile := flag.String("trust-policy", "", "optional root-signed delegated trust policy")
	flag.Parse()
	if *config == "" || *rootFile == "" {
		return errors.New("--config and --root-key-file required")
	}
	read := func(path string, max int64) ([]byte, error) {
		info, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Size() > max {
			return nil, fmt.Errorf("unsafe or oversized file %s", path)
		}
		return os.ReadFile(path)
	}
	raw, e := read(*config, 1024*1024)
	if e != nil {
		return e
	}
	root, e := read(*rootFile, 1024)
	if e != nil {
		return e
	}
	var envelope prestarter.Envelope
	if e = json.Unmarshal(raw, &envelope); e != nil {
		return e
	}
	var policy *prestarter.TrustPolicy
	if *policyFile != "" {
		if envelope.SchemaVersion != "2.0" {
			return errors.New("legacy bootstrap cannot be used with delegated trust policy")
		}
		p, e := read(*policyFile, 128*1024)
		if e != nil {
			return e
		}
		verified, _, e := prestarter.VerifyTrustPolicy(p, strings.TrimSpace(string(root)), time.Now().UTC())
		if e != nil {
			return e
		}
		policy = &verified
	} else if envelope.SchemaVersion == "2.0" {
		return errors.New("delegated bootstrap requires --trust-policy")
	}
	cfg, digest, e := prestarter.VerifyEnvelopeWithPolicy(raw, strings.TrimSpace(string(root)), policy)
	if e != nil {
		return e
	}
	var brand any
	if cfg.Branding != nil {
		brand = map[string]any{"displayName": cfg.Branding.DisplayName, "publisher": cfg.Branding.Publisher,
			"logo": cfg.Branding.LogoPNG != "", "icon": cfg.Branding.IconPNG != "", "splash": cfg.Branding.SplashPNG != "", "locale": cfg.Branding.Locale, "newsCount": len(cfg.Branding.News)}
	}
	result := map[string]any{"status": "verified", "schemaVersion": envelope.SchemaVersion, "projectId": cfg.ProjectID, "profileId": cfg.ProfileID, "channel": cfg.Channel, "payloadSha256": digest, "branding": brand}
	return json.NewEncoder(os.Stdout).Encode(result)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "branding verification failed:", err)
		os.Exit(1)
	}
}
