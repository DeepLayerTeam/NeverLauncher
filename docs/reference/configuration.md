# Справочник конфигурации

**Источник истины:** [`.env.example`](../../.env.example), [`deploy/production/env.production.example`](../../deploy/production/env.production.example), [`deploy/production/docker-compose.yml`](../../deploy/production/docker-compose.yml), код `services/api/internal/config`.

| Группа | Примеры переменных | Замечания |
| --- | --- | --- |
| Environment/API | `NEVERLAUNCHER_ENV`, `NEVERLAUNCHER_HTTP_ADDR`, `NEVERLAUNCHER_PUBLIC_URL` | В production указывайте публичный HTTPS URL |
| Data | `NEVERLAUNCHER_DATABASE_DSN`, `NEVERLAUNCHER_REPOSITORY_DRIVER`, `NEVERLAUNCHER_SQL_DRIVER` | PostgreSQL с постоянным хранилищем |
| Redis | `NEVERLAUNCHER_REDIS_URL`, `NEVERLAUNCHER_REDIS_ADDR` | Надёжная аутентификация и сетевые ограничения |
| Storage | `NEVERLAUNCHER_STORAGE_DRIVER`, `NEVERLAUNCHER_STORAGE_LOCAL_PATH`, `NEVERLAUNCHER_STORAGE_S3_*` | Local или S3, secure access |
| Auth | `NEVERLAUNCHER_AUTH_TOKEN_SECRET`, `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON`, `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID` | Секреты не хранить в Git |
| Federation | `NEVERLAUNCHER_AUTH_SQL_*`, `NEVERLAUNCHER_AUTH_HTTP_*`, `NEVERLAUNCHER_AUTH_OIDC_*`, `NEVERLAUNCHER_AUTH_MICROSOFT_*` | Не задавайте конфликтующие JSON и FILE |
| WebAuthn/CORS | `NEVERLAUNCHER_WEBAUTHN_*`, `NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` | RP/Origin должны совпадать с доменом |
| ServerBridge | `NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED`, `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` | Подписи JAR, ротация identity |
| Guard | `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`, `NEVERLAUNCHER_RUNTIME_VALIDATION_KEYS_JSON` | Не допускайте пустых production trust roots |
| Extensions | `NEVERLAUNCHER_EXTENSION_*` | Host lifecycle, grants, permission secrets |

`deploy/production/.env` исключён из Git. После замены секретов проверяйте docker compose конфигурацию приватно; команда `docker compose config` может напечатать значения в stdout. Точный список полей и defaults всегда проверяйте по текущему файлу конфигурации, а не только этой странице.
