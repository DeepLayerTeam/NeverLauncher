# Production E2E NeverLauncher 0.10.0-P3.2v4

Production E2E запускается командой:

```bash
e2e/scripts/run-minecraft-e2e.sh
```

Сценарий запускает PostgreSQL и API, применяет реальные миграции БД, выполняет bootstrap установки, собирает плагины ServerBridge и поднимает реальные Velocity, Paper и Purpur. Затем через канонический `/api/v1` публикуется Java fixture, NeverRuntime проверяет подписанный манифест закреплённым Ed25519 public key, потоково загружает и хеширует fixture, запускает его и проверяет цепочку `вход -> разрешение -> отзыв -> запрет` для каждой регистрации bridge.

Канонический Compose-файл: `e2e/docker-compose.minecraft-e2e.yml`. Runtime-файлы и отчёты создаются в `e2e/runtime/` и не являются исходниками репозитория.
