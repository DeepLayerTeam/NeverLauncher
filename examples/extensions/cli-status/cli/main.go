package main

// SDK аутентифицируется через LAUNCHER_EXTENSION_HOST_URL и LAUNCHER_EXTENSION_HOST_TOKEN.
// Перед объявленной командой статуса он выполняет POST /v1/hello.

import (
  "context"
  "fmt"
  extensions "gitflic.ru/skif4er/launcher/sdk/cli/go"
)

func main() {
  extensions.Main(extensions.NewApp(
    extensions.Command{Name:"status", Run: func(ctx context.Context, client *extensions.Client, args []string) error {
      var result map[string]any
      if err := client.Capability(ctx, "extension.self", nil, &result); err != nil { return err }
      fmt.Printf("%s %v\n", client.Environment().ExtensionId, result["version"])
      return nil
    }},
  ))
}
