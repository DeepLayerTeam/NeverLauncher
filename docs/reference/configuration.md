# Справочник конфигурации

**Основные источники настроек:** [`.env.example`](../../.env.example), [`deploy/production/env.production.example`](../../deploy/production/env.production.example), [`deploy/production/docker-compose.yml`](../../deploy/production/docker-compose.yml) и код `services/api/internal/config`.

| Группа | Примеры переменных | Примечания |
| --- | --- | --- |
| Окружение и API | `LAUNCHER_ENV`, `LAUNCHER_HTTP_ADDR`, `LAUNCHER_PUBLIC_URL` | В рабочем окружении указывайте публичный HTTPS-адрес |
| Данные | `LAUNCHER_DATABASE_DSN`, `LAUNCHER_REPOSITORY_DRIVER`, `LAUNCHER_SQL_DRIVER` | PostgreSQL с постоянным хранилищем |
| Redis | `LAUNCHER_REDIS_URL`, `LAUNCHER_REDIS_ADDR` | Надёжная аутентификация и сетевые ограничения |
| Хранилище | `LAUNCHER_STORAGE_DRIVER`, `LAUNCHER_STORAGE_LOCAL_PATH`, `LAUNCHER_STORAGE_S3_*` | Локальное хранилище или S3 с защищённым доступом |
| Авторизация | `LAUNCHER_AUTH_TOKEN_SECRET`, `LAUNCHER_AUTH_TOKEN_KEYS_JSON`, `LAUNCHER_AUTH_TOKEN_ACTIVE_KID` | Секреты нельзя хранить в Git |
| Федерация удостоверений | `LAUNCHER_AUTH_SQL_*`, `LAUNCHER_AUTH_HTTP_*`, `LAUNCHER_AUTH_OIDC_*`, `LAUNCHER_AUTH_MICROSOFT_*` | Не задавайте конфликтующие значения JSON и FILE |
| WebAuthn и CORS | `LAUNCHER_WEBAUTHN_*`, `LAUNCHER_CORS_ALLOWED_ORIGINS` | Идентификатор RP и источник должны соответствовать домену |
| ServerBridge | `LAUNCHER_SERVERBRIDGE_HA_REQUIRED`, `LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` | Подписанные JAR и смена удостоверений |
| Guard | `LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`, `LAUNCHER_RUNTIME_VALIDATION_KEYS_JSON` | В рабочем окружении недопустимы пустые корни доверия |
| Расширения | `LAUNCHER_EXTENSION_*` | Жизненный цикл хоста, разрешения, секреты прав доступа |

Файл `deploy/production/.env` исключён из Git. После замены секретов проверяйте конфигурацию Docker Compose в защищённой среде: команда `docker compose config` способна вывести значения секретов в стандартный поток вывода. Актуальный перечень полей и значения по умолчанию необходимо сверять с действующим файлом конфигурации, а не только с этим справочником.
