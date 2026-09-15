# NeverLauncher Desktop 0.10.6

Desktop Launcher — рабочий Tauri/React-клиент NeverLauncher поверх NeverRuntime.

## Основной сценарий

```text
вход -> привязка проекта/профиля -> загрузка пакета -> проверка целостности -> восстановление
     -> определение runtime -> план запуска -> запуск -> сессия ServerBridge
```

Учётные данные серверной сессии хранятся в системном защищённом хранилище. Проверка manifest signature, SHA-256 и pinned Ed25519 public key выполняется fail-closed.

## Проверка

```bash
npm ci
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
```

В составе общего preflight:

```bash
NEVERLAUNCHER_PREFLIGHT_FRONTEND=1 NEVERLAUNCHER_PREFLIGHT_TAURI=1 ./scripts/release/preflight.sh
```
