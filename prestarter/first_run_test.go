package prestarter

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerSignedFirstRun0352(t *testing.T) {
	parts := baseParts()
	cfg := identityConfig(parts)
	cfg.BackendURL = "https://launcher.example.org"
	cfg.ServerID = "velocity-main"
	cfg.ServerHost = "mc.example.org"
	cfg.ServerPort = 25566
	cfg.AutoEnter = true
	signed, root := generateConfig(t, cfg)
	temp := t.TempDir()
	store := &storage{root: filepath.Join(temp, ".launcher-prestarter")}
	p := installer{root: temp, store: store, config: cfg, rawConfig: signed, key: root, gameRoot: filepath.Join(temp, "profiles", "hello", "vanilla")}
	dir, err := p.ensureDesktopConfig("Player_123", false)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(dir, "bootstrap.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != string(signed) {
		t.Fatal("Подписанные данные первоначальной загрузки изменились при передаче")
	}
	verified, _, err := VerifyEnvelope(original, root)
	if err != nil {
		t.Fatal(err)
	}
	if verified.BackendURL != cfg.BackendURL || verified.ServerHost != cfg.ServerHost || !verified.AutoEnter {
		t.Fatal("Потерян подписанный маршрут игрока")
	}
	configRaw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err = json.Unmarshal(configRaw, &settings); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"backendUrl": cfg.BackendURL, "projectId": cfg.ProjectID, "profileId": cfg.ProfileID, "pinnedPublicKey": cfg.ProfilePublicKey, "serverId": cfg.ServerID, "serverHost": cfg.ServerHost} {
		if settings[key] != want {
			t.Fatalf("Компонент %s не подготовлен: получено %v", key, settings[key])
		}
	}
	if settings["serverPort"] != float64(25566) || settings["autoEnter"] != true {
		t.Fatal("Автоматическое подключение из подписанной конфигурации не настроено")
	}
	// Пользовательские настройки переживают корректный перезапуск Prestarter, а проверенный
	// конверт повторно публикуется из подписанной конфигурации владельца.
	settings["memoryMb"] = float64(6144)
	edited, _ := json.Marshal(settings)
	if err = os.WriteFile(filepath.Join(dir, "config.json"), edited, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = p.ensureDesktopConfig("Player_123", false); err != nil {
		t.Fatal(err)
	}
	read, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var restored map[string]any
	_ = json.Unmarshal(read, &restored)
	if restored["memoryMb"] != float64(6144) {
		t.Fatal("Пользовательские настройки были перезаписаны")
	}
	if _, _, err = VerifyEnvelope(original, strings.Repeat("00", 32)); err == nil {
		t.Fatal("Принят неверный корневой ключ доверия")
	}
	original[len(original)-2] ^= 1
	if _, _, err = VerifyEnvelope(original, root); err == nil {
		t.Fatal("Приняты изменённые данные передачи")
	}
}

func TestBootstrapServerPolicy0352(t *testing.T) {
	cfg := identityConfig(baseParts())
	cfg.BackendURL = "https://launcher.example.org"
	cfg.AutoEnter = true
	cfg.ServerID = "velocity-main"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Разрешено автоматическое подключение без публичного адреса и порта")
	}
	cfg.ServerHost = "mc.example.org"
	cfg.ServerPort = 25565
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.ServerHost = "bad/host"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Принят небезопасный адрес сервера")
	}
	cfg.ServerHost = "mc.example.org"
	_, private, _ := ed25519.GenerateKey(nil)
	raw, _ := json.Marshal(cfg)
	if _, err := SignedEnvelope(raw, private); err != nil {
		t.Fatal(err)
	}
}
