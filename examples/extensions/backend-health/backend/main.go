package main

// SDK аутентифицируется через LAUNCHER_EXTENSION_HOST_URL и LAUNCHER_EXTENSION_HOST_TOKEN.
// Перед heartbeat и запросами возможностей он выполняет POST /v1/hello.

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	extensions "gitflic.ru/skif4er/launcher/sdk/backend/go"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client, err := extensions.NewFromEnvironment()
	if err != nil {
		panic(err)
	}
	callback, err := client.StartCallbackServer(nil, nil)
	if err != nil {
		panic(err)
	}
	defer callback.Close(context.Background())
	if _, err = client.Hello(ctx, callback.URL); err != nil {
		panic(err)
	}
	_ = client.Log(ctx, "info", "extension started", map[string]any{"sdk": "0.21.0"})
	go func() { _ = client.HeartbeatLoop(ctx) }()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = client.Health(ctx)
		}
	}
}
