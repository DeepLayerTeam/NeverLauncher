package main

// SDK аутентифицировать с NEVERLAUNCHER_EXTENSION_HOST_URL и NEVERLAUNCHER_EXTENSION_HOST_TOKEN.
// Это выполняет POST /v1/hello до dispatching объявлять состояние команда.

import (
  "context"
  "fmt"
  neverextensions "gitflic.ru/skif4er/neverlauncher/sdk/cli/go"
)

func main() {
  neverextensions.Main(neverextensions.NewApp(
    neverextensions.Command{Name:"status", Run: func(ctx context.Context, client *neverextensions.Client, args []string) error {
      var result map[string]any
      if err := client.Capability(ctx, "extension.self", nil, &result); err != nil { return err }
      fmt.Printf("%s %v\n", client.Environment().ExtensionId, result["version"])
      return nil
    }},
  ))
}
