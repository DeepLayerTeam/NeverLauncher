package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/discordrpc"
	"gitflic.ru/skif4er/launcher/cli/internal/lanmdns"
)

func handleLAN0308(args []string) error {
	if len(args) == 0 {
		return errors.New("Использование: nl lan publish|discover|verify [флаги]")
	}
	cmd := args[0]
	f := flag.NewFlagSet("lan "+cmd, flag.ContinueOnError)
	name := f.String("instance", "Launcher", "Экземпляр DNS-SD (ASCII)")
	endpoint := f.String("url", "", "HTTPS-адрес Backend")
	fingerprint := f.String("fingerprint", "", "Отпечаток сертификата TLS по SHA-256 (hex)")
	pin := f.String("pin", "", "Отдельно настроенный закреплённый отпечаток сертификата")
	duration := f.Duration("timeout", 3*time.Second, "Тайм-аут обнаружения (1–30 с)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) > 0 {
		return errors.New("Неожиданные позиционные аргументы LAN")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "publish":
		u, err := lanmdns.ValidatePublishAddress(*endpoint)
		if err != nil {
			return err
		}
		if !lanmdns.FingerprintOK(*fingerprint) {
			return errors.New("Для публикации необходим отпечаток TLS-сертификата по SHA-256")
		}
		if err := lanmdns.VerifyTLS(ctx, *endpoint, *fingerprint); err != nil {
			return fmt.Errorf("Предварительная проверка TLS-сертификата Backend не пройдена: %w", err)
		}
		port, _ := strconv.Atoi(u.Port())
		fmt.Fprintf(os.Stderr, "Публикация %s через mDNS. Клиенты не доверяют отпечатку из TXT-записи; настройте независимое закрепление отпечатка.\n", *name)
		return lanmdns.Publish(ctx, *name, port, *fingerprint, net.ParseIP(u.Hostname()))
	case "discover":
		endpoints, err := lanmdns.Discover(ctx, *duration)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(endpoints)
	case "verify":
		if *pin == "" {
			return errors.New("Для проверки необходим параметр --pin с отпечатком, полученным независимо от mDNS")
		}
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if err := lanmdns.VerifyTLS(ctx, *endpoint, *pin); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "TLS-сертификат LAN проверен по независимо закреплённому отпечатку")
		return nil
	default:
		return fmt.Errorf("Неизвестная подкоманда LAN %q", cmd)
	}
}

func handleDiscord0308(args []string) error {
	if len(args) == 0 || args[0] != "presence" {
		return errors.New("Использование: nl discord presence --application-id <id> [--details ..] [--state ..] [--interactive]")
	}
	f := flag.NewFlagSet("discord presence", flag.ContinueOnError)
	applicationID := f.String("application-id", "", "Идентификатор приложения разработчика Discord")
	state := f.String("state", "В лаунчере", "Статус активности")
	details := f.String("details", "Launcher", "Подробности активности")
	interactive := f.Bool("interactive", false, "Читать JSON-описания активности из stdin, по одному на строку; null очищает")
	duration := f.Duration("duration", 0, "Длительность сеанса, 0 — до прерывания")
	buttons := f.String("buttons-json", "", "Кнопки активности в JSON (не более двух)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) > 0 {
		return errors.New("Неожиданные позиционные аргументы Discord")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration < 0 {
		return errors.New("Длительность не может быть отрицательной")
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	client, err := discordrpc.NewSession(ctx, *applicationID)
	if err != nil {
		return err
	}
	defer client.Close()
	initial := discordrpc.Activity{State: *state, Details: *details}
	if *buttons != "" {
		if err := json.Unmarshal([]byte(*buttons), &initial.Buttons); err != nil {
			return err
		}
	}
	if err := client.SetActivity(ctx, &initial); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Discord Rich Presence активен (локальный IPC)")
	if !*interactive {
		<-ctx.Done()
		clean, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = client.SetActivity(clean, nil)
		return nil
	}
	// Канал из лаунчера может передавать переходы состояния, пока IPC-сеанс
	// активен. Каждое обновление подтверждается; фиктивной фоновой задачи нет.
	lines := make(chan string)
	readErr := make(chan error, 1)
	refresh := time.NewTicker(60 * time.Second)
	defer refresh.Stop()
	current := &initial
	go func() {
		scan := bufio.NewScanner(os.Stdin)
		scan.Buffer(make([]byte, 4096), 1<<16)
		for scan.Scan() {
			select {
			case lines <- scan.Text():
			case <-ctx.Done():
				return
			}
		}
		if scan.Err() != nil {
			readErr <- scan.Err()
		} else {
			readErr <- io.EOF
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-refresh.C:
			// Повторно сообщайте текущее состояние, чтобы перезапущенный Discord-клиент
			// восстановил его, даже если лаунчер больше не отправлял переходов.
			if err := client.SetActivity(ctx, current); err != nil {
				fmt.Fprintf(os.Stderr, "Discord presence refresh failed: %v\n", err)
			}
		case err := <-readErr:
			clean, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = client.SetActivity(clean, nil)
			cancel()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case line := <-lines:
			if strings.TrimSpace(line) == "" {
				continue
			}
			var activity *discordrpc.Activity
			if strings.TrimSpace(line) != "null" {
				var value discordrpc.Activity
				if err := json.Unmarshal([]byte(line), &value); err != nil {
					return err
				}
				activity = &value
			}
			if err := client.SetActivity(ctx, activity); err != nil {
				return err
			}
			current = activity
		}
	}
}
