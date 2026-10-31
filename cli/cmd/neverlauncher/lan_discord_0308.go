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
		return errors.New("usage: nl lan publish|discover|verify [flags]")
	}
	cmd := args[0]
	f := flag.NewFlagSet("lan "+cmd, flag.ContinueOnError)
	name := f.String("instance", "Launcher", "DNS-SD instance (ASCII)")
	endpoint := f.String("url", "", "HTTPS backend endpoint")
	fingerprint := f.String("fingerprint", "", "SHA-256 TLS certificate fingerprint (hex)")
	pin := f.String("pin", "", "independently configured pinned certificate fingerprint")
	duration := f.Duration("timeout", 3*time.Second, "discovery timeout (1-30s)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) > 0 {
		return errors.New("unexpected LAN positional arguments")
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
			return errors.New("publish requires TLS certificate SHA-256 fingerprint")
		}
		if err := lanmdns.VerifyTLS(ctx, *endpoint, *fingerprint); err != nil {
			return fmt.Errorf("backend TLS certificate preflight failed: %w", err)
		}
		port, _ := strconv.Atoi(u.Port())
		fmt.Fprintf(os.Stderr, "Publishing %s on mDNS. TXT fingerprint is untrusted by clients; configure an independent pin.\n", *name)
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
			return errors.New("verification requires --pin, provisioned outside mDNS")
		}
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if err := lanmdns.VerifyTLS(ctx, *endpoint, *pin); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "LAN TLS certificate verified against externally pinned fingerprint")
		return nil
	default:
		return fmt.Errorf("unknown LAN subcommand %q", cmd)
	}
}

func handleDiscord0308(args []string) error {
	if len(args) == 0 || args[0] != "presence" {
		return errors.New("usage: nl discord presence --application-id <id> [--details ..] [--state ..] [--interactive]")
	}
	f := flag.NewFlagSet("discord presence", flag.ContinueOnError)
	applicationID := f.String("application-id", "", "Discord developer application ID")
	state := f.String("state", "In launcher", "Activity state")
	details := f.String("details", "Launcher", "Activity details")
	interactive := f.Bool("interactive", false, "read newline-separated JSON activities on stdin; null clears")
	duration := f.Duration("duration", 0, "session duration, 0=until interrupted")
	buttons := f.String("buttons-json", "", "JSON activity buttons (max two)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if len(f.Args()) > 0 {
		return errors.New("unexpected Discord positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration < 0 {
		return errors.New("negative duration")
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	client, err := discordrpc.Connect(ctx, *applicationID)
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
	fmt.Fprintln(os.Stderr, "Discord Rich Presence active (local IPC)")
	if !*interactive {
		<-ctx.Done()
		clean, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = client.SetActivity(clean, nil)
		return nil
	}
	// A pipe from the launcher can stream state transitions while the IPC session
	// remains alive. Each update is acknowledged; there is no mock background task.
	lines := make(chan string)
	readErr := make(chan error, 1)
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
		}
	}
}
