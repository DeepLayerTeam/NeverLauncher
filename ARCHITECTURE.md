# Архитектура NeverLauncher

## Области ответственности

```text
                   +-----------------------------+
                   | React Admin / Tauri Desktop |
                   +---------------+-------------+
                                   | HTTP API / манифесты
                        +----------v---------+
                        | Go Backend API     |
                        | auth / projects    |
                        | packages / bridge  |
                        | extensions / ops   |
                        +----+----------+----+
                             |          |
                   PostgreSQL/Redis   Local / S3 storage
                             |
          +------------------+----------------------+
          | ServerBridge plugins / server hosts     |
          +-----------------------------------------+

 Desktop -> NeverRuntime -> manifest verification -> JRE/loader -> Minecraft
             |          -> NeverGuard / platform trust checks
 CLI `nl` -> API, manifests, release tools, ServerBridge, extensions
```

Это логическое представление, а не схема полного сетевого взаимодействия. Подробности URL, DTO, ролей и ошибок определяет [канонический OpenAPI](schemas/openapi.yaml).

## Слои

1. **Presentation:** `apps/admin` (React/Vite/TypeScript), `apps/desktop` (React/Tauri, Rust). Не держите секреты backend в JS или конфигурации фронтенда.
2. **Control plane:** Go-сервис `services/api`. В `internal/httpapi` располагаются маршруты, обработчики и интеграционные сценарии. Доменные операции должны проходить авторизацию, аудит и проверку границ доверия.
3. **Persistence:** PostgreSQL с миграциями; Redis используется там, где требуется распределённое состояние и координация; файлы пакетов — локальное хранилище или S3. In-memory backend не предназначен для production.
4. **Runtime/data plane:** `runtime/neverruntime` отвечает за получение/проверку файлов, Java, загрузчики, запуск и контроль процесса. NeverGuard поставляется как отдельные защитные компоненты.
5. **Server plane:** `plugins/` содержит Gradle-модули мостов для Minecraft-серверов и прокси. Криптографическая идентичность узлов, enrollment и команды относятся к ServerBridge.
6. **Extensions:** backend host, registry, lifecycle, capabilities, permission grants и SDK — `neverextensions`, `services/api/internal`, `sdk`, `examples/extensions`.
7. **Release plane:** `scripts/release`, `scripts/smoke`, `scripts/compatibility`, `e2e`, `.github/workflows`, сертификаты CI.

## Доверенные границы

- **Desktop ↔ Backend:** bearer/session tokens, device proof, проверка доменов, ограничение прав. Локальный ключ устройства должен храниться в native secure storage; привязка к оборудованию зависит от платформы и требует отдельной проверки.
- **Backend ↔ БД/Redis:** сетевые секреты и TLS для внешних соединений; миграции выполняются контролируемо, с резервной копией и планом отката.
- **Backend ↔ ServerBridge:** регистрация узла, свежесть доказательства владения ключом, проверка replay, роли операторов, ограничения команд.
- **Манифесты/обновления ↔ локальная файловая система:** подпись, SHA-256, атомарная/транзакционная замена и восстановление после сбоя.
- **NeverExtensions ↔ ядро:** capabilities/permissions, ограниченные вызовы host API, контроль жизненного цикла и журнал аудита; степень изоляции различается по ОС.

## Правила развития

- `VERSION` — единый источник номера продукта; при обычных документационных изменениях версия не меняется.
- Схема API — `schemas/openapi.yaml` (OpenAPI 3.1.1); изменяя маршруты/DTO, синхронизируйте контракт и тесты.
- Новые миграции должны быть совместимы с существующими данными; не переписывайте уже применённые миграции.
- Учитывайте Windows/Linux/macOS и x86_64/arm64, а не только ОС разработчика.
- Контрактные проверки по совпадению строк не заменяют поведенческие/security-тесты.

Дополнительно: [локальная разработка](docs/development/local-development.md), [аутентификация](docs/authentication/providers.md), [модель доверия](docs/security/trust-model.md), [эксплуатация](docs/administration/operations.md).
