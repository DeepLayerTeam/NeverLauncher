# NeverLauncher Desktop

Desktop Launcher — рабочий Tauri/React-клиент NeverLauncher поверх NeverRuntime.

## Основной сценарий

```text
вход -> привязка проекта/профиля -> загрузка пакета -> проверка целостности -> восстановление
     -> Never session -> Minecraft session exchange -> определение runtime -> authenticated launch
     -> Yggdrasil/authlib-injector и/или сессия ServerBridge
```

Учётные данные Never session хранятся в системном защищённом хранилище. Перед запуском `0.11.9` Desktop получает отдельный Minecraft access token/UUID от Backend и передаёт их NeverRuntime; token не пишется в command preview. Проверка manifest signature, SHA-256 и pinned Ed25519 public key выполняется fail-closed. Authlib-injector подключается только если его JAR присутствует в подписанном manifest.

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
