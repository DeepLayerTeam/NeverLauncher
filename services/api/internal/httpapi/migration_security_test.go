package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
)

func TestMigrationIndependentNeverSigners0336(t *testing.T) {
	seed := sha256.Sum256([]byte("0336 unique test manifest key"))
	cfg := config.Config{AuthTokenActiveKID: "2026-10", AuthTokenKeysJSON: `{"2026-10":"auth-secret-independently-provisioned-123456789"}`, ManifestSigningPrivateKey: hex.EncodeToString(seed[:])}
	kid, pub, err := migrationSigner0336(cfg)
	if err != nil || kid != "2026-10" || len(pub) != 64 {
		t.Fatalf("Проверка действительных подписантов: %s %s %v", kid, pub, err)
	}
	cfg.ManifestSigningPrivateKey = ""
	if _, _, err = migrationSigner0336(cfg); err == nil {
		t.Fatal("Принят ключ манифеста разработчика")
	}
	cfg.ManifestSigningPrivateKey = hex.EncodeToString(seed[:])
	cfg.AuthTokenKeysJSON = ""
	if _, _, err = migrationSigner0336(cfg); err == nil {
		t.Fatal("Принято резервное значение JWT по умолчанию")
	}
	cfg.AuthTokenKeysJSON = `{"2026-10":"weak"}`
	if _, _, err = migrationSigner0336(cfg); err == nil {
		t.Fatal("Принят слишком короткий секрет")
	}
	cfg.AuthTokenKeysJSON = `{"2026-10":"` + strings.Repeat("x", 32) + `","old-kid":"` + strings.Repeat("x", 32) + `"}`
	if _, _, err = migrationSigner0336(cfg); err == nil {
		t.Fatal("Приняты повторяющиеся ключи JWT")
	}
}
