// verify-branding независимо проверяет bootstrap, подписанный владельцем, с помощью
// производственного верификатора Ed25519 Prestarter. Приватные ключи не выводятся.
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
	config := flag.String("config", "", "Путь к bootstrap.signed.json")
	rootFile := flag.String("root-key-file", "", "Путь к установленному публичному корневому ключу Ed25519 (hex)")
	policyFile := flag.String("trust-policy", "", "Необязательная делегированная политика доверия с подписью корневого ключа")
	flag.Parse()
	if *config == "" || *rootFile == "" {
		return errors.New("Обязательны параметры --config и --root-key-file")
	}
	read := func(path string, max int64) ([]byte, error) {
		info, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Size() > max {
			return nil, fmt.Errorf("Небезопасный файл или файл чрезмерного размера: %s", path)
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
			return errors.New("Устаревшую схему начального запуска нельзя использовать с делегированной политикой доверия")
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
		return errors.New("Для делегированного начального запуска необходим параметр --trust-policy")
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
		fmt.Fprintln(os.Stderr, "Ошибка проверки оформления:", err)
		os.Exit(1)
	}
}
