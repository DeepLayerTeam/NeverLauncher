# Справочник конфигурации

**Источник истины:** [`.env.example`](../../.env.example), [`deploy/production/env.production.example`](../../deploy/production/env.production.example), [`deploy/production/docker-compose.yml`](../../deploy/production/docker-compose.yml), код `services/api/internal/config`.

| Группа | Примеры переменных | Замечания |
| --- | --- | --- |
| Environment/API | `LAUNCHER_ENV`, `LAUNCHER_HTTP_ADDR`, `LAUNCHER_PUBLIC_URL` | В production указывайте публичный HTTPS URL |
| Data | `LAUNCHER_DATABASE_DSN`, `LAUNCHER_REPOSITORY_DRIVER`, `LAUNCHER_SQL_DRIVER` | PostgreSQL с постоянным хранилищем |
| Redis | `LAUNCHER_REDIS_URL`, `LAUNCHER_REDIS_ADDR` | Надёжная аутентификация и сетевые ограничения |
| Storage | `LAUNCHER_STORAGE_DRIVER`, `LAUNCHER_STORAGE_LOCAL_PATH`, `LAUNCHER_STORAGE_S3_*` | Local или S3, secure access |
| Auth | `LAUNCHER_AUTH_TOKEN_SECRET`, `LAUNCHER_AUTH_TOKEN_KEYS_JSON`, `LAUNCHER_AUTH_TOKEN_ACTIVE_KID` | Секреты не хранить в Git |
| Federation | `LAUNCHER_AUTH_SQL_*`, `LAUNCHER_AUTH_HTTP_*`, `LAUNCHER_AUTH_OIDC_*`, `LAUNCHER_AUTH_MICROSOFT_*` | Не задавайте конфликтующие JSON и FILE |
| WebAuthn/CORS | `LAUNCHER_WEBAUTHN_*`, `LAUNCHER_CORS_ALLOWED_ORIGINS` | RP/Origin должны совпадать с доменом |
| ServerBridge | `LAUNCHER_SERVERBRIDGE_HA_REQUIRED`, `LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` | Подписи JAR, ротация identity |
| Guard | `LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`, `LAUNCHER_RUNTIME_VALIDATION_KEYS_JSON` | Не допускайте пустых production trust roots |
| Extensions | `LAUNCHER_EXTENSION_*` | Host lifecycle, grants, permission secrets |

`deploy/production/.env` исключён из Git. После замены секретов проверяйте docker compose конфигурацию приватно; команда `docker compose config` может напечатать значения в stdout. Точный список полей и defaults всегда проверяйте по текущему файлу конфигурации, а не только этой странице.
