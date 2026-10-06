# NeverExtensions Backend Go SDK

Production client for Extension Host Protocol v1. The SDK performs authenticated `hello`, heartbeat, structured logs, capability broker calls, durable event subscriptions and loopback event/hook callbacks. It only reads the `NEVERLAUNCHER_EXTENSION_*` environment supplied by the Backend supervisor.

```go
client, err := neverextensions.NewFromEnvironment()
callbacks, err := client.StartCallbackServer(handleEvent, handleHook)
_, err = client.Hello(ctx, callbacks.URL)
go client.HeartbeatLoop(ctx)
```
