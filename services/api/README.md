# NeverLauncher Серверная часть API

## ServerBridge HA Плоскость управления — 0.19.11

Операции управления надёжно хранятся в PostgreSQL и защищены двумя уровнями ограждение: транзакционной строка аренда (`delivery_sequence`, `lease_owner`, `lease_token`) и краткоживущим ключом владения в Redis. При `NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED=true` Redis обязателен: при недоступности coordinator запуск и control-запросы завершаются отказ с блокировкой. Все API-реплики используют общие PostgreSQL и Redis и уникальный `NEVERLAUNCHER_REPLICA_ID`; ACK/возобновление состояние хранится вне процесса API, поэтому Мост может переподключиться к любой реплике.

Серверная часть предоставляет один production-контракт: `/api/v1`. Исторические маршрутизаторы `/api/v2`–`/api/v5` не регистрируются.

### Обновление 0.14.5 → 0.14.6

Остановите 0.14.5 API экземпляры, примените `nl db migrate apply` и убедитесь через `nl db migrate verify`, что текущий миграция — `0026_fabric_server_bridge_0146`. Обновите релиз список разрешений отдельным `fabricSha256`, зарегистрируйте Fabric узел с `kind=fabric`, установите сервер-только Fabric мост и Fabric API, затем регистрировать публичный Ed25519 ключ и дождитесь подписанный сигнал состояния. Закрытый ключ не передаётся Серверная часть.

### Обновление 0.14.4 → 0.14.5

Остановите 0.14.4 API экземпляры, примените `nl db migrate apply` и убедитесь через `nl db migrate verify`, что текущий миграция — `0025_proxy_family_0145`. Обновите релиз список разрешений точными SHA-256 `velocity/bungeecord/waterfall/bukkit/spigot/paper/purpur/folia`, установите соответствующий платформе прокси JAR и дождитесь подписанный сигнал состояния каждого узел. BungeeCord/Waterfall используют отдельные узел идентичности; закрытый Ed25519 ключи остаются только на соответствующем прокси.


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

## Bukkit семейство ServerBridge — 0.14.4

Серверная часть 0.14.4 принимает Протокол v2 узлы типов `velocity`, `bukkit`, `spigot`, `paper`, `purpur` и `folia`. Для каждого типа релиз список разрешений хранится отдельно, поэтому SHA-256 JAR одной платформы нельзя использовать как целостность измерение другой. Начиная с политика версия `0.14.4`, рабочий запуск отказ с блокировкой требует все шесть непустых allowlist-массивов.

Миграция `0024_bukkit_family_0144` атомарно расширяет PostgreSQL `server_bridge_nodes_v2.kind` ограничение и сохраняет существующие узел идентичности, одноразовые значения и одноразовый билеты. `/api/v1/server-bridge/plugins` публикует отдельные artifacts/configs для всей Bukkit семейство и указывает Folia-безопасный среда выполнения. Среда выполнения платформа несоответствие блокируется самим плагин до сигнал состояния; Серверная часть по-прежнему повторно проверяет Ed25519 идентичность, артефакт измерение и билет привязка при каждом подключение.

## Одноразовый Подключение Билеты — 0.14.3

ServerBridge подключение авторизация в 0.14.3 является реальным одноразовым учётные данные, а не только короткоживущей сессия строка. Серверная часть генерирует 192-бит CSPRNG `jt_...` билет, в PostgreSQL привязывает его к текущим `identity_epoch` и Ed25519 отпечаток ключа узел и при первом успешном подписанный validate/has-joined атомарно переводит строка из `active` в `consumed`. В использованный состояние сохраняются идентичность epoch/fingerprint, SHA-256 уже проверенного одноразовый узел одноразовое значение и IP использование; повторный или параллельный использование не может пройти тот же conditional `UPDATE`. Ротация узел идентичность также делает старый билет непригодным.

Yggdrasil-compatible `/sessionserver/session/minecraft/join` → `/hasJoined` теперь имеет ту же одноразовое использование семантику: IP/trust/integrity проверки выполняются до consumption, а первый валидный `/hasJoined` атомарно погашает авторизация. Миграция `0023_one_time_join_tickets_0143` отказ с блокировкой инвалидирует старые активный ServerBridge билеты и удаляет временный `minecraft_joins` 0.14.2, потому что для них нельзя доказать, что `/hasJoined` ранее не воспроизводился.

## ServerBridge Криптографический Узел Идентичности — 0.14.2

ServerBridge Протокол v2 использует PostgreSQL источник истины из 0.14.1, но узел аутентификация в 0.14.2 полностью переведён с общий bearer секрет на Ed25519. При регистрации/регистрация Серверная часть принимает только сырой открытый ключ, вычисляет SHA-256 отпечаток и хранит его вместе с `identity_epoch`; закрытый ключ остаётся в локальном `node-identity.properties` Velocity или Bukkit/Spigot/Paper/Purpur/Folia мост.

Сигнал состояния, проверять-подключение, имеет-подключение и плагин аудит подписываются канонический полезная нагрузка `NeverLauncher-ServerBridge-Node-v1` с метод, escaped path/query, точный тело SHA-256, метка времени и random одноразовое значение. Серверная часть проверяет ограниченный clock skew, Ed25519 signature/fingerprint и атомарно consume-ит одноразовое значение в `server_bridge_node_nonces_v2`; повторное воспроизведение возвращает `409`. Миграция `0022_serverbridge_crypto_node_identities_0142` retire-ит устаревший токен хеширует и требует явный `rotate-identity` регистрация для существующих 0.14.1 узлы.

## Авторизация и администрирование

Канонический API реализует login/refresh/logout, отзыв сессий, роли, пароль/TOTP/recovery-сценарии, CRUD проектов/профилей/каналов, пользователей, аудит, проверку хранилища, публикацию версий и операции с пакетами в `/api/v1/auth/*` и `/api/v1/admin/*`.

Начиная с `0.11.1`, при PostgreSQL репозиторий аутентификация состояние больше не хранится в локальный для процесса реестр: `auth_sessions`, токен обновления families/tokens, TOTP методы и восстановление код используют PostgreSQL как источник истины. Ротация сохраняет использованный обновление токены; повторное воспроизведение уже использованного токен компрометирует всю семейство и отзывает сессия. TOTP секреты хранятся зашифрованными в `mfa_methods`, восстановление код — отдельно как хеширует. Память аутентификация серверная часть оставлен только для dev/test режима.

Начиная с `0.11.2`, вход проходит через Федерация Ядро: коннектор подтверждает учётные данные и возвращает провайдер идентичность, затем `(provider, subject)` разрешается через `auth_identities` в канонического Никогда пользователь, и только после этого создаётся Никогда сессия. Встроенный `local` провайдер реализован через публичный `pkg/authconnector`; `/api/v1/auth/providers` отдаёт среда выполнения реестр, а `/api/v1/auth/identities` — связи текущего пользователя. Внешние провайдер токены не принимаются как Никогда доступ токены.

Начиная с `0.11.3`, Федерация Ядро умеет регистрировать реальные SQL провайдеры из `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE`. SQL Коннектор поддерживает PostgreSQL, MySQL и MariaDB, выполняет только построенные NeverLauncher prepared/bound только для чтения запросы по валидированному сопоставление, имеет отдельные connect/query тайм-аут и pool ограничения, проверяет TLS политика и поддерживает Argon2ID, bcrypt, PBKDF2-SHA256 и явно разрешённый устаревший SHA-256. При `provisioning.mode=jit` первый успешный вход атомарно создаёт канонический Никогда пользователь + `auth_identity`; совпадение электронная почта с существующим Никогда пользователь считается конфликтом и не приводит к неявному учётная запись связывание.

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

По умолчанию SQL провайдер требует TLS с проверкой сертификата. `allowInsecureTls: true` разрешает только зашифрованное соединение без строгой проверки сертификата (`sslmode=require`/эквивалент) и предназначено для контролируемых development/staging окружений; открытый текст требует отдельного `requireTls: false`. В рабочий рекомендуется только для чтения DB учётная запись и `dsnEnv`, а не DSN с паролем внутри JSON. `legacy-sha256` принимается только вместе с `password.allowLegacySha256=true`.

Начиная с `0.11.4`, Федерация Ядро также регистрирует рабочий HTTP провайдеры из `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE`. Это не webhook и не общий прокси: Коннектор вызывает только заранее заданные HTTPS эндпоинты `/authenticate`, `/refresh`, `/resolve`, `/logout`, `/health`, подписывает каждый запрос HMAC-SHA256 и принимает только подписанные JSON ответы с ожидаемыми `issuer`, протокол версия, одноразовое значение и метка времени. Перенаправления отключены, тело ответа ограничен по размеру, JSON декодируется строгий схема decoder.

HTTP Коннектор использует собственный транспорт без окружение прокси, проверяет `hostAllowlist`, сам разрешает DNS, валидирует каждый IP до dial и блокирует private/loopback/link-local/shared/reserved сети. Контролируемый закрытый эндпоинт разрешается только явным `allowedCidrs`. Дополнительный CA и необязательный mTLS клиентский сертификат поддерживаются через `mtls.caFile/certFile/keyFile`. `providerToken` остаётся учётные данные внешнего провайдер и не используется как Никогда access/refresh токен. Полный протокол и канонический HMAC strings описаны в `internal/httpconnector/README.md`.

Пример HTTP провайдер:

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

Начиная с `0.11.5`, Федерация Ядро также регистрирует рабочий OIDC провайдеры из `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_FILE`. Коннектор использует OpenID Провайдер Обнаружение, Авторизация Код Поток + PKCE `S256`, обязательные `state`/`nonce`, JWKS и полную проверку ID Токен (`iss`, `aud`, `azp`, `exp`, `nbf`, `iat`, подпись, `nonce`). `none` и HMAC ID Токен algorithms не принимаются. Обнаружение/JWKS/token/UserInfo вызываются усиленный транспорт без окружение прокси, с список разрешённых хостов, DNS/IP валидация, TLS 1.2+ и явным `allowedCidrs` для контролируемых закрытый IdP.

Для desktop/web API доступны `POST /api/v1/auth/oidc/{providerId}/begin` и `POST /api/v1/auth/oidc/{providerId}/complete`. PKCE verifier/nonce находятся внутри короткоживущего AEAD транзакция токен, поэтому поток не зависит от локальный для процесса состояние и работает между несколькими Серверная часть экземпляры. Для обычного браузера есть `GET.../start` + `GET.../callback`; транзакция хранится в HttpOnly SameSite=Lax cookie.

Пример OIDC провайдер:

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

`provisioning.mode=explicit-only` остаётся безопасным по умолчанию: совпадение электронная почта не связывает внешний аккаунт с существующим Никогда пользователь. `jit` создаёт новый канонический пользователь только после успешной криптографической проверки OIDC идентичность. Внешний groups/roles сохраняются как идентичность захватывает, но не могут самостоятельно повысить глобальную Никогда роль: JIT роль задаётся локальной `defaultRole`.

Начиная с `0.11.6`, Microsoft идентичность платформа подключается отдельным `microsoftconnector`, который использует тот же OIDC движок, но добавляет Microsoft-specific доверие правила. Конфигурация задаётся через `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE`. Поддерживаются `common`, `organizations`, `consumers` и tenant GUID, а также global/US Gov/China clouds. Для multitenant метаданные проверяются `tid`, tenant-specific `iss` и `issuer` ключ подписи из JWKS. Канонический субъект формируется как `tid:oid`; электронная почта/UPN не используются как идентичность ключ.

Пример Microsoft провайдер:

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

`offline_access` включается Коннектор автоматически. Полученный Microsoft токен обновления не возвращается клиенту: Серверная часть шифрует его AES-GCM и сохраняет в `provider_credentials`. Для существующего Никогда пользователь используется аутентифицировать связывание поток `POST /api/v1/auth/microsoft/{providerId}/link/begin` и `/link/complete`; провайдер учётные данные можно ротировать через `POST /api/v1/auth/providers/{providerId}/credential/refresh`. Microsoft front-канал выход URL выдаётся отдельно через `/api/v1/auth/microsoft/{providerId}/logout-url` и не заменяет Никогда выход. Microsoft подпись-в сам по себе **не означает владение Minecraft**; entitlement/profile проверка остаётся отдельным слоем.

## Ключи доступа / WebAuthn + MFA 2.0

Начиная с `0.11.7`, Серверная часть поддерживает discoverable passkeys/WebAuthn с обязательным пользователь проверка. RP настраивается через `NEVERLAUNCHER_WEBAUTHN_RP_ID`, `NEVERLAUNCHER_WEBAUTHN_RP_NAME` и `NEVERLAUNCHER_WEBAUTHN_ORIGINS`. Registration/login/step-up запросы одноразовые и в рабочий хранятся в PostgreSQL. Доступны passwordless ключ доступа вход, MFA continuation после пароль/OIDC/Microsoft аутентификация, управление учётные данные и политика `optional|required|phishing-resistant`.

Сессия фиксирует `authMethods`, `authStrength` и `authTime`. Step-up не изменяет уже выданный токен доступа: после успешного TOTP/recovery/passkey Серверная часть выпускает новый токен доступа для той же сервер сессия. Критические publish/restore/sign/role/token-rotation эксплуатация проверяют актуальность и требуемую силу аутентификация перед выполнением.

## Сессия Управление 2.0

Начиная с `0.11.8`, Никогда токен доступа — compact JWS/JWT с `kid`, issuer/audience валидация и session/authentication захватывает. Ротация ключей настраивается через `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` + `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID`; старый ключ можно оставить только для проверка до истечения ранее выпущенных доступ токены.

`GET /api/v1/auth/sessions` возвращает постоянный device/provider/auth/risk метаданные и отмечает текущую сессия. `PATCH /api/v1/auth/sessions/{sessionId}` переименовывает устройство, `DELETE` отзывает одну сессия, `POST /api/v1/auth/sessions/revoke-others` отзывает остальные. Администратор сессия API поддерживает фильтры `userId`, `providerId`, `status`, `riskState` и массовый отзыв; провайдер-wide отзыв требует актуальный устойчивый к фишингу step-up. IP/User-Agent расхождение повышает риск до `elevated`, обновление повторное воспроизведение — до `compromised` с семейство отзыв.

`POST /api/v1/auth/providers/{providerId}/logout` выполняет только провайдер-побочный отзыв сохранённого провайдер учётные данные, если коннектор поддерживает отзыв. Эта операция намеренно не отзывает Никогда сессия; для неё используется отдельный Никогда logout/session отзыв.

## Minecraft Аутентификация Совместимость 2.0

Начиная с `0.11.10`, миграция совместимость проверяется до рабочий startup/upgrade как отдельный релиз concern. Серверная часть `dbmigrate.StatusOf` различает ожидающий обновление и несовместимое состояние (`unknown`, `unverified`, контрольная сумма расхождение), а миграция `0010_federation_stabilization_01110` отказ с блокировкой проверяет существующие refresh-family/session/provider-credential связи до добавления ограничения. CLI-команды `nl db migrate apply` и `nl db migrate verify` используют тот же встроенный миграция каталог и контрольная сумма, что Серверная часть.

Федерация контроль выпуска запускается через `python3 scripts/test/federation-e2e.py`; реальный restart/multi-instance PostgreSQL сценарий — через `bash e2e/scripts/run-federation-postgres-e2e.sh`. Последний выполняет login/refresh/replay/revoke через Серверная часть A/B/C и проверяет схема `verify` до и после сценария.

Начиная с `0.11.9`, Minecraft profile/session отделены от Никогда сессия и от конкретного способа аутентификации. `POST /api/v1/minecraft/session` с разрешение `profile:launch` обменивает действующую Никогда сессия на непрозрачный `nlmc_*` токен доступа и постоянный Профиль Minecraft. В PostgreSQL хранится только SHA-256 токен хеш; Minecraft сессия ссылается на родительский `auth_sessions`, поэтому logout/revoke Никогда сессия сразу делает игровой токен недействительным.

Minecraft UUID стабильно выводится из канонический Никогда пользователь ID и не зависит от email/provider субъект. Yggdrasil-compatible `/authserver/*` и `/sessionserver/session/minecraft/*` используют тот же постоянный адаптер. Пароль провайдеры идут через Федерация Ядро; OIDC/Microsoft/passkey не требуют повторного локального пароль вход и используют сессия обмен. `join/hasJoined` хранится в PostgreSQL, повторно проверяет родительский Никогда сессия и поддерживает необязательный IP привязка.

Корень `/` отдаёт authlib-injector метаданные. Для стандартного Minecraft authlib NeverRuntime может подключить только `authlib-injector*.jar`, присутствующий в подписанном релиз манифест; Настольное приложение передаёт среда выполнения выданные Серверная часть UUID/токен доступа, а команда preview редактирует учётные данные.

## Пакеты и манифесты

Создание пакета, загрузка файлов, валидация, подпись, подготовка, быстрая проверка, публикация и откат канала доступны через `/api/v1/packages/*` и `/api/v1/channels/*`. Опубликованные манифесты подписываются Ed25519 и проверяются NeverRuntime по закреплённому открытый ключ.

## ServerBridge

Velocity и Bukkit/Spigot/Paper/Purpur/Folia используют `/api/v1/server-bridge/*`, `/api/v1/session/*` и `/api/v1/textures/*` для регистрации, сигнал состояния, проверки входа, инвалидирования сессий и получения текстур.

## Операции

Диагностика, реальный PostgreSQL/storage резервное копирование, проверочный восстановление пробный запуск, подтверждаемый восстановление, аудит экспорт, diagnostic комплект и compliance доступны через `/api/v1/operations/*`. `/ready` работает отказ с блокировкой при несовместимых миграциях PostgreSQL и при недоступном Redis rate ограничитель в рабочий отказ с блокировкой режиме.

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

Канонические HTTP интеграционные тесты находятся в `services/api/internal/httpapi/*_test.go` и напрямую проверяют `/api/v1`, включая аутентификация, CRUD, публикацию пакетов, безопасность усиление защиты, резервное копирование и ServerBridge. Исторические `/api/v2`–`/api/v5` проверяются как отсутствующие.

```bash
go test ./...
go test -race ./...
go vet ./...
go build -trimpath ./cmd/neverlauncher-api
```

Для offline-окружения без рабочий SQL драйвер (`pgx`/MySQL) в локальном модуль кэш:

```bash
go test -tags neverlauncher_nopgx ./...
go vet -tags neverlauncher_nopgx ./...
```

Рабочий CI всегда собирает обычный pgx-бинарник; `neverlauncher_nopgx` не является резервный вариант для production-релиза.

### Защита миграция / совместимость стабилизация 0.13.10

Миграция `0020_guard_migration_compatibility_stabilization_01310.sql` закрепляет сохранённый Minecraft Защита снимок как атомарный DB состояние. Перед добавлением ограничения она отказ с блокировкой проверяет существующие 0.13.9 строки: проверен сессия должна иметь доверенный устройство, четыре канонический SHA-256, лаунчер версия и допустимый аттестация метка времени; non-проверен сессия не может содержать частичный Защита снимок. После миграция те же инварианты применять PostgreSQL-ом, а `/ready`/миграция инструментарий требуют запечатанный `0020`.

Среда выполнения совместимость fix включает macOS в `guardAttestationRequiredForDevice` для последующей Minecraft/ServerBridge reevaluation; это устраняет расхождение с уже существующим macOS `guard-attest` выдача путь.

### Миграция стабилизация 0.12.10

Миграция `0018_device_trust_stabilization_01210.sql` исправляет PostgreSQL ограничение для замена запрос назначение (`key-rotate`, `key-recover`), переводит необязательный replacement/Minecraft устройство ссылки на SQL `NULL` и закрепляет владение между доверенный устройство, аутентификация сессия, замена цепочка, Minecraft сессия и профиль через составной внешний ключи. Перед установкой ограничения миграция отказ с блокировкой проверяет существующие данные и нормализует только однозначно безопасные устаревший revoked/challenge состояния.

Репозиторий пути для `replaced_by_device_id` и `minecraft_sessions.trusted_device_id` используют `sql.NullString`/NULL writer семантика. Точный-обновление E2E создаёт схема `0.12.9` из `0001..0017` и применяет `0018` поставка CLI, поэтому миграция путь проверяется отдельно от актуальный-установка тесты.

### Кроссплатформенная ротация и восстановление ключей 0.12.8

Серверная часть реализует два определяемый сервером замена поток. `key-rotation` проверяет подписи старого и нового ключа по одному канонический запрос; `key-recovery` требует актуальный устойчивый к фишингу step-up и доказательство staged-новым ключом. SQL репозиторий выполняет замена одной транзакцией и сохраняет постоянный замена цепочка через миграция `0017_device_key_recovery_rotation_0128.sql`. Текущая сессия перепривязывается к новой идентичность с увеличенным `binding_epoch`, остальные учётные данные старой идентичность отзываются.

Desktop/Tauri хранит подготовленный ключ отдельно от активный ключ и commit-ит его только после Серверная часть успех. Оборудование генерация получают разные метки; прерванный локальный фиксация восстанавливается через отпечаток согласование. Ordinary регистрация из уже привязанный сессия не используется как обход замена.

### Minecraft / ServerBridge доверие принудительное применение 0.12.7

Серверная часть 0.12.7 pin-ит каждый новый Minecraft сессия к `trusted_device_id + binding_epoch` родительский Никогда сессия. Официальный `POST /api/v1/minecraft/session` требует привязанный проверен устройство; устаревший Yggdrasil аутентифицировать может сохранить протокол совместимость, но `/sessionserver/session/minecraft/join` всё равно отказ с блокировкой применяет игровой доверие политика.

`validateMinecraftToken119`, Yggdrasil `hasJoined`, `/api/v1/session/has-joined` и `/api/v1/server-bridge/validate-join` выполняют актуальный `session-device-risk-v1` evaluation. Постоянный mismatch/revoke инвалидирует устаревший учётные данные, а `reattest/step-up` возвращает recoverable запрещать. На стороне сервера проверяет не вызывают игрок сеть observation, поэтому IP/UA мост сервер не создаёт ложный риск расхождение. ServerBridge подключение фиксирует устройство эпоха и `project/profile/channel`; плагин валидация дополнительно проверяет канал equality.

Миграция `0016_minecraft_serverbridge_trust_0127.sql` добавляет `trusted_device_id` и `binding_epoch` в `minecraft_sessions` и backfill-ит существующие записи из `auth_sessions`. HTTP регрессионные тесты и контроль `minecraft-serverbridge-trust-0127.py` проверяют unbound запрещать, re-привязывать инвалидация, актуальный риск запрещать и канал закрепление.

### Привязка сессии к устройству и интеграция риска 0.12.6

Серверная часть 0.12.6 хранит `binding_epoch` в `auth_sessions` и включает его в JWT. `verifyAdminToken` и запрос observation сверяют JWT привязка с на стороне сервера сессия, а registration/re-bind увеличивает эпоха. Старый JWT после изменения привязка больше не принимается.

Для сессия с `trusted_device_id` обновление требует `deviceId + deviceSignature`. Подпись проверяется до ротация по канонический `NeverLauncher Session Device Binding v1` полезная нагрузка (`user/session/device/binding_epoch/refresh-token-sha256`). Неверный доказательство не расходует токен обновления; использованный-токен повторное воспроизведение сохраняет семейство-wide компрометация семантика. Риск evaluation объединяет IP/User-Agent расхождение, доверенное устройство состояние, оборудование-аттестация актуальность и обновление повторное использование в `risk_score` + `risk_action`; критичный эндпоинты выполняют `step-up/reattest/revoke` политика. Миграция: `0015_session_device_risk_0126.sql`.

### Устройство Управление + Отзыв 0.12.5

Серверная часть 0.12.5 делает устройство отзыв единым безопасность жизненный цикл. Пользовательские управление эндпоинты: `GET /api/v1/auth/devices?status=active|revoked`, `PATCH /api/v1/auth/devices/{deviceId}`, `POST /api/v1/auth/devices/{deviceId}/revoke`, `POST /api/v1/auth/devices/revoke-others`; совместимый `DELETE` также выполняет постоянный отзыв. `revoke-others` требует, чтобы текущая сессия была привязана к активный проверен доверенный устройство, которое и сохраняется.

Для PostgreSQL доверенное устройство метка удаления, consumption открытых устройство запросы, отзыв связанных аутентификация сессии, обновление families/tokens и Minecraft сессии выполняются в одной транзакции с блокировки строк. После фиксация ServerBridge подключается затронутых Никогда сессии инвалидируются. API возвращает реальные каскад счётчики. Отозванный отпечаток ключа повторно зарегистрировать нельзя; переподключение требует нового ключ. Администратор list/revoke находится под `/api/v1/admin/auth/devices*`, а отзыв защищён актуальный устойчивый к фишингу step-up. Новая миграция для 0.12.5 не требуется.

### Запрос-ответ аттестация 0.12.4

Серверная часть добавляет отдельные `POST /api/v1/auth/devices/{deviceId}/attest/begin|complete`. Они доступны только активный сессия, которая уже связана с тем же проверен доверенный устройство. Постоянный `attest` запрос привязан к сессия и сохранённым ключ properties, имеет TTL 2 минуты и одноразовый семантика; подпись проверяется зарегистрированным P-256 открытый ключ.

Успех сохраняет `attestation_state=verified`, `attestation_method=challenge-response-v1` и 12-часовой актуальность окно через миграция `0014_challenge_response_attestation_0124.sql`. Актуальный состояние отражается в JWT и `/api/v1/auth/device-trust` как `challenge-response-attested`; после истечение действующий уверенность снова `proof-of-possession`. Аттестация не повышает RBAC/MFA/аутентификация сила.

Эта процедура доказывает свежое владение уже зарегистрированным привязанный к оборудованию ключ, но не поставщик TPM/Защищённый Анклав происхождение: платформа подписант не предоставляет Серверная часть проверяемый quote/certificate, поэтому `hardwareProvider` остаётся метаданные и API явно возвращает `hardwareProvenance=not-remotely-verified`.

Базовый `0.12.3` устройство доказательство продолжает принимать `ed25519/software` и `p256/hardware`; оборудование привязка сам по себе аттестация не создаёт.

### Доверие к устройству 0.12.2

Серверная часть хранит доверенный устройства отдельно от устаревший сессия `deviceId`. Registration/verification использует постоянный одноразовый запрос и Ed25519 подпись; успешный доказательство связывает текущую Никогда сессия с `trusted_device_id` и обновляет JWT устройство захватывает. Пользовательские эндпоинты находятся под `/api/v1/auth/devices*`, административный реестр — `/api/v1/admin/auth/devices`. Отзыв устройство отзывает связанные session/refresh семейство.

Начиная с `0.12.2` официальный Настольное приложение автоматически создаёт устройство ключ в нативный OS защищённый хранилище и выполняет эти процедура после login/restore. Серверная часть по-прежнему получает только открытый ключ и подписи и не повышает уверенность выше `proof-of-possession`: факт использования защищённый хранилище не является оборудование аттестация. Миграция `0012_device_trust_core_0121` остаётся достаточной для на стороне сервера постоянный схема; `0.12.2` не требует новой DB миграция.

### Аутентификация Федерация 0.12

Стабильный реестр создаётся через `httpapi.NewFederationCore(...)`; Локальный/SQL/HTTP/OIDC/Microsoft проходят Коннектор SDK соответствие до приёма трафика. Общий browser идентичность связывание доступен через `/api/v1/auth/providers/{providerId}/link/begin|complete`, а `/api/v1/admin/auth/federation/status` показывает среда выполнения работоспособность и предоставление учётной записи политика провайдеры. Миграция `0011_auth_federation_release_0120` закрепляет канонический локальный идентичность для поддерживающий пароль пользователи.

### Minecraft / ServerBridge целостность принудительное применение (0.13.5)

Minecraft сессия теперь сохраняет проверен Защита снимок (`attestation/evidence/guard/launcher SHA-256`, релиз версия и проверка время). `/api/v1/session/join` связывает ServerBridge подключение с конкретным `minecraftAccessToken`; для Windows Защита-применять устройство отсутствие такой связи возвращает `412`. Minecraft/Yggdrasil/ServerBridge валидация заново проверяет снимок по текущему Защита релиз список разрешений, поэтому удаление хеш отзывает уже активные игровые учётные данные.

ServerBridge сигнал состояния и `POST /api/v1/server-bridge/validate-join` передают SHA-256 реально загруженного плагин JAR. Серверная часть хранит только измерение, подтверждённый `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`, и live-перепроверяет его при каждом подключение. Рабочий конфигурация без Мост список разрешений отклоняется. Релиз конвейер генерирует `BRIDGE_RELEASE_ALLOWLIST.json` из финальных Velocity/BungeeCord/Waterfall/Bukkit/Spigot/Paper/Purpur/Folia/Fabric JAR.

### Защита Аттестация серверная часть контроль (0.13.4)

`POST /api/v1/auth/devices/{deviceId}/guard-attest/begin|complete` реализуют запрос-ответ проверка Windows NeverGuard. Серверная часть хранит запрос и запускать билет в том же постоянный DeviceChallenge репозиторий с атомарный использовать семантика. Полный требует свежую оборудование P-256 устройство аттестация, проверяет устройство подпись, evidence/attestation хеши, процесс boundary/policy и релиз SHA-256 список разрешений. При включённой Защита политика `POST /api/v1/minecraft/session` требует одноразовый `guardAttestationTicket` для Windows доверенный устройство; Linux/macOS не притворяются поддерживающими Windows Защита. В рабочий `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` обязателен.

### NeverGuard релиз политика 0.14.0

Серверная часть `0.14+` принимает Защита политика только в `schemaVersion=2.0`: `releases.<version>.protocolVersion=4`, платформа пространство имён `windows|linux|macos`, `signingMode` и точный `artifacts[]` пары (`guardSha256` + `launcherSha256`). Рабочий Windows требует `authenticode`/`requireAuthenticode=true`, macOS — `developer-id-notarized`, Linux — `integrity-only`. Устаревший независимый хеш список остаются только для запуска 0.13.x Серверная часть и не принимаются 0.14+.
