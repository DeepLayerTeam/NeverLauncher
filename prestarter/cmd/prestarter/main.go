package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/DeepLayerTeam/Launcher/prestarter"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

// Заменяется при компиляции через -ldflags -X. Пустой встроенный ключ доверия намеренно
// блокирует производственный bootstrap до настройки корня доверия.
var embeddedRootPublicKey string
var version = "0.47.7"

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
	flag.StringVar(&opts.TrustPolicyPath, "trust-policy", "", "локальная делегированная политика доверия с подписью корневым ключом (не удалённый URL)")
	flag.StringVar(&opts.ConfigPath, "config", defaultConfig, "путь к локальной подписанной конфигурации первоначального запуска")
	flag.StringVar(&opts.Root, "root", defaultRoot, "абсолютный путь к каталогу данных приложения")
	flag.StringVar(&opts.OfflineDir, "offline-dir", "", "необязательный локальный проверенный архив сборки")
	flag.BoolVar(&opts.Offline, "offline", false, "запретить доступ к сети")
	flag.BoolVar(&opts.LaunchProfile, "launch-profile", false, "запустить подписанный автономный профиль Minecraft")
	flag.StringVar(&opts.Username, "username", "", "имя игрока Minecraft для автономного режима (нужен --launch-profile)")
	flag.BoolVar(&opts.NoDesktop, "no-desktop", false, "только подготовить, восстановить и установить, без запуска Desktop")
	var operatorKey string
	flag.StringVar(&operatorKey, "operator-root-public-key", "", "явно заданный локальный корень доверия для операторской сборки (не может заменить встроенный ключ)")
	flag.Parse()
	opts.TrustedKey = embeddedRootPublicKey
	if opts.TrustedKey == "" {
		opts.TrustedKey = operatorKey
	} else if operatorKey != "" && operatorKey != embeddedRootPublicKey {
		fmt.Fprintln(os.Stderr, "Ключ оператора конфликтует со встроенным корневым ключом")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := prestarter.Run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "prestarter "+version+": "+err.Error())
		os.Exit(1)
	}
	fmt.Println("Первоначальная настройка Launcher завершена")
}

func applicationRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(base) {
			return filepath.Join(base, "Launcher"), nil
		}
		return filepath.Join(home, "AppData", "Local", "Launcher"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Launcher"), nil
	default:
		if base := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(base) {
			return filepath.Join(base, "Launcher"), nil
		}
		return filepath.Join(home, ".local", "share", "Launcher"), nil
	}
}
