# Аутентификация и внешние провайдеры

Backend включает внутреннюю auth-систему, поддержку SQL/HTTP/OIDC-провайдеров, федерацию Microsoft identity, MFA/WebAuthn, сессии и device trust. Реальная доступность способа входа зависит от конкретной конфигурации и тестов.

| Вариант | Конфигурация | Особенности |
| --- | --- | --- |
| Встроенные аккаунты | `NEVERLAUNCHER_AUTH_TOKEN_*` | Выдача и отзыв токенов, политика сессий |
| SQL | `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `_FILE` | Изолированные DSN и проверка password hashing |
| Live FileAuthSystem (read-only) | `NEVERLAUNCHER_AUTH_FILE_PROVIDERS_JSON` или `_FILE` | Файл Gravit `Database.json`, динамическое обновление и точный формат паролей |
| HTTP | `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` или `_FILE` | HTTPS, host allowlist и подписанные ответы |
| OIDC | `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON` или `_FILE` | Authorization Code + PKCE, issuer/JWKS validation |
| Microsoft identity | `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` или `_FILE` | Федерация учётной записи; **не тождественна** владению Minecraft Java Edition |
| Passkeys/WebAuthn | `NEVERLAUNCHER_WEBAUTHN_RP_*`, `NEVERLAUNCHER_WEBAUTHN_ORIGINS` | HTTPS и RP ID, соответствующий домену |

## Различие между Microsoft login и Minecraft login

Аутентификация Microsoft OAuth/OIDC удостоверяет идентичность пользователя. Получение Minecraft-токена и подтверждение ownership/profile — отдельная цепочка. Не считайте наличие федерации Microsoft готовой официальной Minecraft-аутентификацией без end-to-end проверок Minecraft Services.

## Рекомендации по защите

Секреты провайдеров передавайте через secret manager/окружение. Не смешивайте JSON и FILE-конфиг одного провайдера, если обработчик запрещает это. Ограничивайте redirect URI, origins и host allowlist. Используйте короткие сессии, отзыв, аудит и защиту от replay. Актуальные примеры ключей и названий параметров: [`.env.example`](../../.env.example), [`deploy/production/env.production.example`](../../deploy/production/env.production.example).

## Provider Routing & Account Linking (0.29.3)

`POST /api/v1/auth/login` принимает `identifier`, `password` и необязательный `providerId`. Если `providerId` передан, выбирается **только** он. Если не передан, применяются точные правила `emailDomain`, затем `defaultProvider`. Для несопоставленного identifier настройка `requireExplicitProvider: true` требует `providerId`; по умолчанию сохраняется `local` для обратной совместимости. Ошибки пароля, отказ/недоступность, отсутствие identity и конфликты **никогда** не вызывают попытку входа в другом провайдере.

Настройка передаётся через `NEVERLAUNCHER_AUTH_ROUTING_JSON` **или** `NEVERLAUNCHER_AUTH_ROUTING_FILE`:

```json
{
  "version": 1,
  "defaultProvider": "local",
  "requireExplicitProvider": false,
  "rules": [
    { "emailDomain": "company.example", "providerId": "website", "strict": true }
  ],
  "linkingAllowProviders": ["website"]
}
```

Маршрутизация применяется к **password login**. OIDC/Microsoft browser login уже требует явный `providerId` в URL, привязан к серверной PKCE/state/nonce transaction и не подбирает провайдер по email. Если в конфигурации задан `strict: true`, указание другого провайдера при входе с соответствующим email отклоняется. `strict: false` разрешает явно выбрать другой провайдер, не разрешая fallback. Правила проверяют строку email-идентификатора; они **не** доказывают владение доменом или email.

Для привязки используются только `POST /api/v1/auth/providers/{providerId}/link/password` (с действительной Never-сессией и новым успешным паролем внешнего провайдера) либо `link/begin` + `link/complete` (с действительной Never-сессией, привязанной browser PKCE transaction и подтверждённой external identity). `linkingAllowProviders` задаёт allowlist для обоих потоков; опциональный `disableLinking: true` полностью запрещает новые привязки, не затрагивая вход или безопасное обновление credentials уже связанных identity. Без этих полей существующее явное связывание остаётся разрешённым. Указание произвольного email, username или subject без provider proof **не** связывает аккаунты. Повторная привязка `(provider, issuer, subject)` к чужому Never user и смена subject текущего `(user, provider, issuer)` запрещены. Различные issuer никогда не объединяются по одинаковому email.

Конфигурация валидируется при старте: неизвестные/не password-capable provider, некорректные/дублирующиеся домены, неизвестные версии, конфликт JSON+FILE и превышение 64 KiB останавливают запуск, не активируя частичное правило. При изменении маршрутизации проверяйте реальные login + explicit linking на тестовых учётных записях до доставки на production; конфигурация применяется при перезапуске Backend. Для защиты от обхода через имя пользователя без email задавайте `requireExplicitProvider: true` и полагайтесь на авторизацию уже проверенного identity/issuer.

## SQL Mapping & Legacy Hash (0.29.4)

Configure **one explicit password verifier per SQL provider**. Existing `argon2id`, `bcrypt`, `pbkdf2-sha256`, and opt-in `legacy-sha256` continue to work. In addition, Launcher supports Gravit `digest`, `doubleDigest`, and portable WordPress PHPass (`$P$`, `$H$`) from AdditionalHash. Digest algorithms are explicitly selected from `md5`, `sha1`, `sha256`, `sha512`; the recorded text format is `hex` (default) or canonical padded `base64`. `doubleDigestHex: true` hashes the lowercase hexadecimal representation of the first digest; `false` hashes its raw bytes. These Gravit digests are **unsalted**, while PHPass stores its salt and iteration count inside the hash. Do not assume that custom CMS salts, custom password verifiers, or arbitrary Gravit module extensions are compatible.

```json
[
  {
    "id": "gravit-site",
    "driver": "postgresql",
    "dsnEnv": "GRAVIT_SQL_DSN",
    "table": "public.accounts",
    "columns": {
      "id": "uuid",
      "username": "username",
      "email": "email",
      "password": "password_hash",
      "status": "status",
      "minecraftUuid": "minecraft_uuid"
    },
    "password": {
      "algorithm": "doubleDigest",
      "digestAlgorithm": "SHA256",
      "digestEncoding": "hex",
      "doubleDigestHex": true,
      "allowLegacyHashes": true
    },
    "provisioning": {"mode":"explicit-only"}
  }
]
```

Use `password: {"algorithm":"phpass","allowLegacyHashes":true}` for WordPress `$P$`/`$H$` hashes. PHPass rejects custom cost values outside log2 iterations 7–17 to prevent CPU exhaustion; bcrypt remains a separate verifier. For Gravit `digest` use `algorithm: "digest"` and choose the exact algorithm/encoding. Legacy unsalted digests (especially MD5/SHA-1) are weak: enable only for an existing, explicitly reviewed database behind TLS, short-lived Never sessions and constrained SQL permissions. Never writes back hashes to external SQL in 0.29.4, nor does it silently rehash or reset passwords. Controlled Argon2id conversion is a separate 0.29.5 milestone, and only Never-owned records may be rewritten with authorization.

On startup the SQL connector opens a **read-only transaction** and executes a zero-row `SELECT` of the configured columns. The database driver must confirm that the table and each configured column exists, and the password/Minecraft UUID mappings must not be a binary database type. Missing columns, insufficient permissions, or schema mismatch fail the provider's startup rather than waiting for a login attempt. The diagnostic mapping preview contains only logical field names, mapped column names, and SQL column types — never example rows or password hashes. SQL identifiers are validated and quoted per dialect; login values remain bound SQL parameters. A prepared query and the runtime connection-health check follow successful schema validation.

Run live tests with `NEVERLAUNCHER_SQL_TEST_POSTGRES_DSN`, `NEVERLAUNCHER_SQL_TEST_MYSQL_DSN`, and `NEVERLAUNCHER_SQL_TEST_MARIADB_DSN` pointing to isolated disposable test databases. The `sql-mapping-legacy-hash-0294.yml` workflow provisions all three engines and must pass wrong-password, correct-password, mapping-failure, and unknown-hash fail-closed cases before a production rollout. Gravit reference: https://gravitlauncher.com/auth/ (PasswordVerifier); AdditionalHash: https://github.com/GravitLauncher/LauncherModules.


## Live Gravit FileAuthSystem — 0.42.6

Never can authenticate directly against a **read-only** Gravit `FileAuthSystem/Database.json`; the previous one-time import remains available. The connector is opt-in, separate from the `local` provider, and does not consume `Sessions.json`. The Gravit UUID is the immutable external identity subject and `minecraftUuid` claim. Never issues its own sessions, and does **not** import Gravit administrator roles, access tokens, permissions, skins, or source sessions.

```sh
NEVERLAUNCHER_AUTH_FILE_PROVIDERS_JSON='[{"id":"gravit-files","displayName":"Gravit FileAuth","databasePath":"/run/neverlauncher/gravit/FileAuthSystem/Database.json","passwordFormat":"phpass","provisioning":{"mode":"jit","defaultRole":"player"}}]'
```

Use only one of `NEVERLAUNCHER_AUTH_FILE_PROVIDERS_JSON` and `NEVERLAUNCHER_AUTH_FILE_PROVIDERS_FILE` (the latter contains the same JSON array). `databasePath` must be absolute, end with `Database.json`, and point to a regular file that is **not world-readable**. For Docker, bind-mount the actual file or its containing directory read-only; environment values alone do not mount host paths. `passwordFormat` is mandatory and cannot be `auto` (supported explicit formats are defined in `internal/fileauth`). `provisioning.mode: "explicit-only"` is the default, requiring prior authenticated account linking; `jit` creates a Never account with *only* its configured default Never role, usually `player`. For production, set an explicit provider routing rule or require an explicit `providerId`.

The connector verifies the source on startup, hashes and checks its bytes before each login/lookup, reuses an immutable parsed snapshot only if the exact content is unchanged, and **fails closed** for missing, corrupted, replaced-during-read, symlinked, oversized or unreadable files. Use atomic replacement (write a private temporary file, fsync, then rename) for source updates; editing `Database.json` in place may produce transient authentication errors. A FileAuth password changed in the source takes effect on the next authentication. An already issued Never session is independent and remains subject to Never's session lifetime/revocation policy; changing the source password alone is **not** an immediate Never-session revocation.

Legacy Gravit `digest` and `doubleDigest` are intentionally password verifiers, **not** secure new password storage methods. Never's imported local accounts rehash valid legacy credentials to Argon2id with atomic CAS on the first successful login. A live read-only FileAuth provider **cannot** rewrite the upstream hash: migrate users to Never-owned accounts to perform such upgrades. PHPass and supported legacy digest combinations are explicit; unknown third-party CMS salts, arbitrary Gravit JAR logic and custom password formats are not supported. The live provider does not write authentication state to the Gravit source, and is not a binary-compatible Gravit Java module.
