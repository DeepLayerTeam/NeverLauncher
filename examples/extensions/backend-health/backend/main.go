package main

// The SDK authenticates with NEVERLAUNCHER_EXTENSION_HOST_URL and NEVERLAUNCHER_EXTENSION_HOST_TOKEN.
// It performs POST /v1/hello before starting heartbeat and capability traffic.

import (
  "context"
  "os/signal"
  "syscall"
  "time"

  neverextensions "gitflic.ru/skif4er/neverlauncher/sdk/backend/go"
)

func main() {
  ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
  defer stop()
  client, err := neverextensions.NewFromEnvironment()
  if err != nil { panic(err) }
  callback, err := client.StartCallbackServer(nil, nil)
  if err != nil { panic(err) }
  defer callback.Close(context.Background())
  if _, err = client.Hello(ctx, callback.URL); err != nil { panic(err) }
  _ = client.Log(ctx, "info", "extension started", map[string]any{"sdk":"0.20.10"})
  go func(){ _ = client.HeartbeatLoop(ctx) }()
  ticker := time.NewTicker(30*time.Second); defer ticker.Stop()
  for { select { case <-ctx.Done(): return; case <-ticker.C: _, _ = client.Health(ctx) } }
}
