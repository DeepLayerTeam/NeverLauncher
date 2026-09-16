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

Начиная с `0.11.6`, Microsoft identity platform подключается отдельным `microsoftconnector`, который использует тот же OIDC engine, но добавляет Microsoft-specific trust rules. Конфигурация задаётся через `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE`. Поддерживаются `common`, `organizations`, `consumers` и tenant GUID, а также global/US Gov/China clouds. Для multitenant metadata проверяются `tid`, tenant-specific `iss` и `issuer` signing key из JWKS. Canonical subject формируется как `tid:oid`; email/UPN не используются как identity key.

Пример Microsoft provider:

```json
[
  {
    "id": "microsoft",
    "cloud": "global",
    "tenant": "organizations",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "clientSecretEnv": "MICROSOFT_CLIENT_SECRET",
    "redirectUris": ["https://launcher.example.com/api/v1/auth/oidc/microsoft/callback"],
    "postLogoutRedirectUris": ["https://launcher.example.com/"],
    "allowedTenantIds": ["11111111-2222-3333-4444-555555555555"],
    "provisioning": {"mode":"explicit-only"}
  }
]
```

`offline_access` включается Connector автоматически. Полученный Microsoft refresh token не возвращается клиенту: Backend шифрует его AES-GCM и сохраняет в `provider_credentials`. Для существующего Never user используется authenticated linking flow `POST /api/v1/auth/microsoft/{providerId}/link/begin` и `/link/complete`; provider credential можно ротировать через `POST /api/v1/auth/providers/{providerId}/credential/refresh`. Microsoft front-channel logout URL выдаётся отдельно через `/api/v1/auth/microsoft/{providerId}/logout-url` и не заменяет Never logout. Microsoft sign-in сам по себе **не означает владение Minecraft**; entitlement/profile verification остаётся отдельным слоем.

## Passkeys / WebAuthn + MFA 2.0

Начиная с `0.11.7`, Backend поддерживает discoverable passkeys/WebAuthn с обязательным user verification. RP настраивается через `NEVERLAUNCHER_WEBAUTHN_RP_ID`, `NEVERLAUNCHER_WEBAUTHN_RP_NAME` и `NEVERLAUNCHER_WEBAUTHN_ORIGINS`. Registration/login/step-up challenges одноразовые и в production хранятся в PostgreSQL. Доступны passwordless passkey login, MFA continuation после password/OIDC/Microsoft auth, управление credentials и policy `optional|required|phishing-resistant`.

Сессия фиксирует `authMethods`, `authStrength` и `authTime`. Step-up не изменяет уже выданный access token: после успешного TOTP/recovery/passkey Backend выпускает новый access token для той же server session. Критические publish/restore/sign/role/token-rotation operations проверяют freshness и требуемую силу authentication перед выполнением.

## Session Management 2.0

Начиная с `0.11.8`, Never access token — compact JWS/JWT с `kid`, issuer/audience validation и session/authentication claims. Key rotation настраивается через `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` + `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID`; старый key можно оставить только для verification до истечения ранее выпущенных access tokens.

`GET /api/v1/auth/sessions` возвращает persistent device/provider/auth/risk metadata и отмечает текущую session. `PATCH /api/v1/auth/sessions/{sessionId}` переименовывает устройство, `DELETE` отзывает одну session, `POST /api/v1/auth/sessions/revoke-others` отзывает остальные. Admin session API поддерживает фильтры `userId`, `providerId`, `status`, `riskState` и массовый revoke; provider-wide revoke требует fresh phishing-resistant step-up. IP/User-Agent drift повышает risk до `elevated`, refresh replay — до `compromised` с family revoke.

`POST /api/v1/auth/providers/{providerId}/logout` выполняет только provider-side revoke сохранённого provider credential, если connector поддерживает revoke. Эта операция намеренно не отзывает Never session; для неё используется отдельный Never logout/session revoke.

## Minecraft Auth Compatibility 2.0

Начиная с `0.11.10`, migration compatibility проверяется до production startup/upgrade как отдельный release concern. Backend `dbmigrate.StatusOf` различает pending upgrade и несовместимое состояние (`unknown`, `unverified`, checksum drift), а migration `0010_federation_stabilization_01110` fail-closed проверяет существующие refresh-family/session/provider-credential связи до добавления constraints. CLI-команды `nl db migrate apply` и `nl db migrate verify` используют тот же embedded migration catalog и checksum, что Backend.

Federation release gate запускается через `python3 scripts/test/federation-e2e.py`; реальный restart/multi-instance PostgreSQL сценарий — через `bash e2e/scripts/run-federation-postgres-e2e.sh`. Последний выполняет login/refresh/replay/revoke через Backend A/B/C и проверяет schema `verify` до и после сценария.

Начиная с `0.11.9`, Minecraft profile/session отделены от Never session и от конкретного способа аутентификации. `POST /api/v1/minecraft/session` с permission `profile:launch` обменивает действующую Never session на opaque `nlmc_*` access token и persistent Minecraft profile. В PostgreSQL хранится только SHA-256 token hash; Minecraft session ссылается на parent `auth_sessions`, поэтому logout/revoke Never session сразу делает игровой token недействительным.

Minecraft UUID стабильно выводится из canonical Never user ID и не зависит от email/provider subject. Yggdrasil-compatible `/authserver/*` и `/sessionserver/session/minecraft/*` используют тот же persistent adapter. Password providers идут через Federation Core; OIDC/Microsoft/passkey не требуют повторного локального password login и используют session exchange. `join/hasJoined` хранится в PostgreSQL, повторно проверяет parent Never session и поддерживает optional IP binding.

Root `/` отдаёт authlib-injector metadata. Для стандартного Minecraft authlib NeverRuntime может подключить только `authlib-injector*.jar`, присутствующий в подписанном release manifest; Desktop передаёт runtime выданные Backend UUID/access token, а command preview редактирует credential.

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

### Device Trust 0.12.1

Backend хранит trusted devices отдельно от legacy session `deviceId`. Registration/verification использует persistent single-use challenge и Ed25519 signature; успешный proof связывает текущую Never session с `trusted_device_id` и обновляет JWT device claims. Пользовательские endpoints находятся под `/api/v1/auth/devices*`, административный registry — `/api/v1/admin/auth/devices`. Revoke device отзывает связанные session/refresh families.

Migration `0012_device_trust_core_0121` обязательна для persistent production режима. Assurance `proof-of-possession` не является hardware attestation.

### Auth Federation 0.12

Stable registry создаётся через `httpapi.NewFederationCore(...)`; Local/SQL/HTTP/OIDC/Microsoft проходят Connector SDK conformance до приёма трафика. Generic browser identity linking доступен через `/api/v1/auth/providers/{providerId}/link/begin|complete`, а `/api/v1/admin/auth/federation/status` показывает runtime health и provisioning policy providers. Migration `0011_auth_federation_release_0120` закрепляет canonical local identity для password-capable users.
