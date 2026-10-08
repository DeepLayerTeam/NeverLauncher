# NeverExtensions Серверная часть Go SDK

Рабочий клиент для Хост расширений Протокол v1. SDK выполняет аутентифицировать `hello`, сигнал состояния, структурированный журналы, возможность broker вызов, долговременный событие subscriptions и локальная петля event/hook обратный вызов. Это только читает `NEVERLAUNCHER_EXTENSION_*` окружение supplied через Серверная часть супервизор.

```go
client, err := neverextensions.NewFromEnvironment()
callbacks, err := client.StartCallbackServer(handleEvent, handleHook)
_, err = client.Hello(ctx, callbacks.URL)
go client.HeartbeatLoop(ctx)
```
