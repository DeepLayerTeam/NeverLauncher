# NeverLauncher Backend API

Backend предоставляет один production-контракт: `/api/v1`. Исторические маршрутизаторы `/api/v2`–`/api/v5` не регистрируются.

## Публичные маршруты и установка

```text
GET  /health
GET  /ready
GET  /metrics
GET  /api/v1/status
GET  /api/v1/runtime/requirements
GET  /api/v1/loaders
GET  /api/v1/install/wizard
GET  /api/v1/install/profiles
GET  /api/v1/install/readiness
POST /api/v1/install/bootstrap-admin
POST /api/v1/install/first-project
```

## Авторизация и администрирование

Канонический API реализует login/refresh/logout, отзыв сессий, роли, password/TOTP/recovery-сценарии, CRUD проектов/профилей/каналов, пользователей, аудит, проверку хранилища, публикацию версий и операции с пакетами в `/api/v1/auth/*` и `/api/v1/admin/*`.

Начиная с `0.11.1`, при PostgreSQL repository auth state больше не хранится в process-local registry: `auth_sessions`, refresh-token families/tokens, TOTP methods и recovery codes используют PostgreSQL как source of truth. Rotation сохраняет consumed refresh tokens; replay уже использованного token компрометирует всю family и отзывает session. TOTP secrets хранятся зашифрованными в `mfa_methods`, recovery codes — отдельно как hashes. Memory auth backend оставлен только для dev/test режима.

Начиная с `0.11.2`, login проходит через Federation Core: connector подтверждает credentials и возвращает provider identity, затем `(provider, subject)` разрешается через `auth_identities` в канонического Never user, и только после этого создаётся Never session. Встроенный `local` provider реализован через публичный `pkg/authconnector`; `/api/v1/auth/providers` отдаёт runtime registry, а `/api/v1/auth/identities` — связи текущего пользователя. Внешние provider tokens не принимаются как Never access tokens.

Начиная с `0.11.3`, Federation Core умеет регистрировать реальные SQL providers из `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE`. SQL Connector поддерживает PostgreSQL, MySQL и MariaDB, выполняет только построенные NeverLauncher prepared/bound read-only запросы по валидированному mapping, имеет отдельные connect/query timeout и pool limits, проверяет TLS policy и поддерживает Argon2id, bcrypt, PBKDF2-SHA256 и явно разрешённый legacy SHA-256. При `provisioning.mode=jit` первый успешный вход атомарно создаёт canonical Never user + `auth_identity`; совпадение email с существующим Never user считается конфликтом и не приводит к неявному account linking.

Пример provider-конфигурации:

```json
[
  {
    "id": "website",
    "displayName": "Website account",
    "driver": "postgresql",
    "dsnEnv": "WEBSITE_AUTH_DATABASE_DSN",
    "table": "public.users",
    "columns": {
      "id": "id",
      "username": "username",
      "email": "email",
      "password": "password_hash",
      "status": "status",
      "displayName": "display_name",
      "groups": "groups",
      "roles": "roles",
      "minecraftUuid": "minecraft_uuid"
    },
    "password": {"algorithm": "bcrypt"},
    "activeStatusValues": ["active", "1"],
    "provisioning": {"mode": "jit", "defaultRole": "player"},
    "requireTls": true,
    "connectTimeout": "5s",
    "queryTimeout": "3s",
    "maxOpenConns": 10,
    "maxIdleConns": 2
  }
]
```

По умолчанию SQL provider требует TLS с проверкой сертификата. `allowInsecureTls: true` разрешает только зашифрованное соединение без строгой проверки сертификата (`sslmode=require`/эквивалент) и предназначено для контролируемых development/staging окружений; plaintext требует отдельного `requireTls: false`. В production рекомендуется read-only DB account и `dsnEnv`, а не DSN с паролем внутри JSON. `legacy-sha256` принимается только вместе с `password.allowLegacySha256=true`.

Начиная с `0.11.4`, Federation Core также регистрирует production HTTP providers из `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE`. Это не webhook и не generic proxy: Connector вызывает только заранее заданные HTTPS endpoints `/authenticate`, `/refresh`, `/resolve`, `/logout`, `/health`, подписывает каждый request HMAC-SHA256 и принимает только подписанные JSON responses с ожидаемыми `issuer`, protocol version, nonce и timestamp. Redirects отключены, response body ограничен по размеру, JSON декодируется strict schema decoder.

HTTP Connector использует собственный transport без environment proxy, проверяет `hostAllowlist`, сам разрешает DNS, валидирует каждый IP до dial и блокирует private/loopback/link-local/shared/reserved сети. Контролируемый private endpoint разрешается только явным `allowedCidrs`. Дополнительный CA и optional mTLS client certificate поддерживаются через `mtls.caFile/certFile/keyFile`. `providerToken` остаётся credential внешнего provider и не используется как Never access/refresh token. Полный protocol и canonical HMAC strings описаны в `internal/httpconnector/README.md`.

Пример HTTP provider:

```json
[
  {
    "id": "website-http",
    "displayName": "Website account",
    "baseUrl": "https://auth.example.com/v1",
    "issuer": "website-auth-prod",
    "hostAllowlist": ["auth.example.com"],
    "hmac": {
      "keyId": "neverlauncher-prod",
      "secretEnv": "WEBSITE_AUTH_HTTP_HMAC_SECRET",
      "maxClockSkew": "2m"
    },
    "requestTimeout": "5s",
    "connectTimeout": "3s",
    "maxResponseBytes": 1048576,
    "provisioning": {"mode": "jit", "defaultRole": "player"}
  }
]
```

Начиная с `0.11.5`, Federation Core также регистрирует production OIDC providers из `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_FILE`. Connector использует OpenID Provider Discovery, Authorization Code Flow + PKCE `S256`, обязательные `state`/`nonce`, JWKS и полную проверку ID Token (`iss`, `aud`, `azp`, `exp`, `nbf`, `iat`, signature, `nonce`). `none` и HMAC ID Token algorithms не принимаются. Discovery/JWKS/token/UserInfo вызываются hardened transport без environment proxy, с host allowlist, DNS/IP validation, TLS 1.2+ и явным `allowedCidrs` для контролируемых private IdP.

Для desktop/web API доступны `POST /api/v1/auth/oidc/{providerId}/begin` и `POST /api/v1/auth/oidc/{providerId}/complete`. PKCE verifier/nonce находятся внутри короткоживущего AEAD transaction token, поэтому flow не зависит от process-local state и работает между несколькими Backend instances. Для обычного браузера есть `GET .../start` + `GET .../callback`; transaction хранится в HttpOnly SameSite=Lax cookie.

Пример OIDC provider:

```json
[
  {
    "id": "company-oidc",
    "displayName": "Company SSO",
    "issuer": "https://id.example.com/realms/company",
    "clientId": "neverlauncher",
    "clientSecretEnv": "OIDC_CLIENT_SECRET",
    "tokenEndpointAuthMethod": "client_secret_basic",
    "redirectUris": ["https://launcher.example.com/api/v1/auth/oidc/company-oidc/callback"],
    "hostAllowlist": ["id.example.com"],
    "scopes": ["openid", "profile", "email"],
    "claims": {"subject":"sub","email":"email","username":"preferred_username","displayName":"name","groups":"groups","roles":"roles"},
    "roleMappings": {"neverlauncher-admins":"admin"},
    "requireVerifiedEmail": true,
    "userInfoMode": "optional",
    "allowedIdTokenAlgs": ["RS256", "PS256", "ES256", "EdDSA"],
    "provisioning": {"mode":"jit","defaultRole":"player"}
  }
]
```

`provisioning.mode=explicit-only` остаётся безопасным default: совпадение email не связывает внешний аккаунт с существующим Never user. `jit` создаёт новый canonical user только после успешной криптографической проверки OIDC identity. External groups/roles сохраняются как identity claims, но не могут самостоятельно повысить глобальную Never role: JIT role задаётся локальной `defaultRole`.

## Пакеты и манифесты

Создание пакета, загрузка файлов, валидация, подпись, staging, smoke-test, публикация и rollback канала доступны через `/api/v1/packages/*` и `/api/v1/channels/*`. Опубликованные манифесты подписываются Ed25519 и проверяются NeverRuntime по закреплённому public key.

## ServerBridge

Velocity/Paper/Purpur используют `/api/v1/server-bridge/*`, `/api/v1/session/*` и `/api/v1/textures/*` для регистрации, heartbeat, проверки входа, инвалидирования сессий и получения текстур.

## Операции

Диагностика, реальный PostgreSQL/storage backup, проверочный restore dry-run, подтверждаемый restore, audit export, diagnostic bundle и compliance доступны через `/api/v1/operations/*`. `/ready` работает fail-closed при несовместимых миграциях PostgreSQL и при недоступном Redis rate limiter в production fail-closed режиме.

## Контракт

Канонический контракт хранится в:

```text
schemas/openapi.yaml
```

Перегенерация и проверка по фактическому router:

```bash
python3 scripts/contracts/generate_openapi.py
python3 scripts/contracts/validate-openapi.py
```

## Тесты

Канонические HTTP integration tests находятся в `services/api/internal/httpapi/*_test.go` и напрямую проверяют `/api/v1`, включая auth, CRUD, публикацию пакетов, security hardening, backup и ServerBridge. Исторические `/api/v2`–`/api/v5` проверяются как отсутствующие.

```bash
go test ./...
go test -race ./...
go vet ./...
go build -trimpath ./cmd/neverlauncher-api
```

Для offline-окружения без production SQL drivers (`pgx`/MySQL) в локальном module cache:

```bash
go test -tags neverlauncher_nopgx ./...
go vet -tags neverlauncher_nopgx ./...
```

Production CI всегда собирает обычный pgx-бинарник; `neverlauncher_nopgx` не является fallback для production-релиза.
