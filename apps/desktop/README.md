# NeverLauncher Desktop

Desktop Launcher — рабочий Tauri/React-клиент NeverLauncher поверх NeverRuntime.

## Основной сценарий

```text
вход -> привязка проекта/профиля -> загрузка пакета -> проверка целостности -> восстановление
     -> Never session -> Minecraft session exchange -> определение runtime -> authenticated launch
     -> Yggdrasil/authlib-injector и/или сессия ServerBridge
```

Учётные данные Never session хранятся в native OS secure storage. Для device identity Desktop сначала пытается создать non-exportable P-256 key в platform HSM (Secure Enclave/TPM); если hardware backend недоступен, используется совместимый Ed25519 key в native OS secure storage. Private key создаётся и используется только внутри Tauri: React получает public fingerprint/binding/provider и подпись конкретного Backend challenge, но не private key material. После login/restore Desktop автоматически регистрирует либо повторно подтверждает trusted device; для P-256/hardware затем выполняется отдельный `challenge-response-v1` attestation с 12-часовой freshness. Эта ceremony подтверждает владение зарегистрированным hardware key, но не заявляет vendor TPM/Secure Enclave provenance.

Перед запуском Desktop получает отдельный Minecraft access token/UUID от Backend и передаёт их NeverRuntime; token не пишется в command preview. Проверка manifest signature, SHA-256 и pinned Ed25519 public key выполняется fail-closed. Authlib-injector подключается только если его JAR присутствует в подписанном manifest.

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
