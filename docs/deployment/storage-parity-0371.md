# Launcher 0.37.1 — проверяемая карта зависимостей и реальные контракты хранилищ

## Что поставляется

Это **исполняемая** инвентаризация текущей кодовой базы, а не заявление о готовности SQLite-only HTTP Backend.

- `scripts/storageparity/main.go` обходит Go-код Go AST-парсером, выделяет используемые SQL-открытия, PostgreSQL-драйверы, потенциально PostgreSQL-специфичные запросы и конфигурацию. Для SQL, shell, Python, CI и конфигурационных файлов дополнительно фиксируются текстовые маркеры с реальными путями и строками.
- `docs/deployment/storage-dependencies-0371.json` — детерминированный исходный снимок обнаруженных зависимостей и surface методов. В нём **пути, номера строк и фрагменты исходника**, а не придуманные классификации в таблице.
- `services/api/internal/storageparity/*_test.go` запускает **один и тот же набор действий** против SQLite Core на диске и настоящего PostgreSQL с миграциями. Ни mock, ни memory fallback не принимаются.
- `.github/workflows/ci.yml` запускает проверку снимка и оба теста в отдельном обязательном job с PostgreSQL 18; `required-ci` зависит от успеха этого job.

## Обнаруженная граница HTTP ↔ SQLite

Снимок исходников 0.37.1:

- `repository.Repository`: **112 методов** (сигнатуры текущего HTTP API).
- `sqlitecore.Repository`: **76 именованных методов**. **13 имён** совпадают с HTTP Repository, однако у SQLite Core и HTTP API разные сигнатуры. Совпадение имени **не является ни реализацией интерфейса, ни подтверждением семантического parity**.
- **99 имён HTTP Repository не найдены** в SQLite Core. Это только сравнение конкретных двух интерфейсов, не доказательство отсутствия отдельных вспомогательных store-реализаций.
- В картотеке обнаружены PostgreSQL-ориентированные миграции и прямые зависимости (включая конфигурацию и CLI). Общее число файлов с совпавшими маркерами не равно числу блокирующих зависимостей: некоторые файлы содержат только тестовые fixtures или SQLite SQL.

Полный список — `methodSurface.httpRepositoryMethods`, `methodSurface.sqliteCoreMethods`, `methodSurface.httpRepositoryMethodsWithoutSQLiteCoreName` в JSON. К каждому найденному source marker привязаны `path`, `line`, `category`, `evidence`.

### Основные блокирующие точки подключения (проверять в следующей версии)

| Место | Конкретная оставшаяся зависимость |
| --- | --- |
| `services/api/cmd/launcher-api/main.go` | HTTP bootstrap выбирает память/SQLRepository; SQLite Core нельзя выдавать за Repository |
| `services/api/internal/deployment/mode.go` | `single-node` явно блокируется до гарантий полного SQLite HTTP backend |
| `services/api/internal/httpapi/installation.go` | Установка и первичная настройка открывают SQL-подключение напрямую |
| `services/api/internal/httpapi/auth_core_postgres_111.go` | Отдельные операции авторизации и сессий реализованы через PostgreSQL |
| `services/api/internal/httpapi/webauthn_store_117.go` | Хранилище WebAuthn связано с SQL handle |
| `services/api/internal/httpapi/persistence.go` | PostgreSQL-связанные операции сохранения состояния |
| `services/api/internal/httpapi/operations_backup.go` | Обслуживание и backup используют зависимости текущей топологии |
| `services/api/internal/repository/*.go` | SQLRepository и дополнительные store интерфейсы, включая устройства, публикацию, Bridge, расширения, миграции |
| `services/api/internal/dbmigrate/sql/*.sql` | PostgreSQL SQL миграции; нельзя исполнять их как SQLite |
| `services/api/internal/sqlitepg/transfer.go` | Перенос между движками не эквивалентен готовому cutover backend |
| `services/api/internal/sqlitedurable/*` | Гарантии WAL/FS; самостоятельное хранилище не означает HTTP parity |

## Реальные общие поведенческие тесты

Тесты выполняют одинаковую программу на двух адаптерах с реальными соединениями:

1. Сохранение проекта и повторная запись без потери исходного `createdAt`.
2. Создание профиля, ревизия, неизменяемые исторические snapshots.
3. Отклонение stale revision при CAS.
4. Два параллельных обновления одной ревизии: ровно одно побеждает.
5. Сохранение учётной записи с project-scoped ролью и её отключение.
6. Закрытие хранилища, **новое открытие**, проверка сохранности проекта, истории профиля, статуса пользователя и роли.

Это **ограниченный проверяемый срез**. Тесты не подтверждают готовность SQLite stable publish, полноценного OAuth/MFA HTTP, расширений, Bridge, WebAuthn, durable jobs или всех 112 методов. Для этих подсистем необходимы отдельные parity/negative/E2E проверки до снятия блокировки single-node.

## Использование

```bash
# Из корня репозитория: проверка полной карты исходников
GO111MODULE=off go test ./scripts/storageparity -count=1
GO111MODULE=off go run ./scripts/storageparity -root . -check

# Из корня: после осознанного изменения кода обновить карту и ревьюить diff
GO111MODULE=off go run ./scripts/storageparity -root .

# Из services/api: реальные SQLite + PostgreSQL контракты
# DSN должен указывать только на одноразовую тестовую БД!
LAUNCHER_PARITY_POSTGRES_DSN='postgres://...test-database...' \
LAUNCHER_STORAGE_PARITY_REQUIRED=1 \
LAUNCHER_SQLITE_TEST_ROOT=/absolute/path/on/ext4 \
go test -race -count=1 -v ./internal/storageparity
```

Проверка `-check` не обновляет карту и завершится ошибкой при любом изменении зафиксированной поверхности. При новом SQL-коде сначала инспектируется зависимость и отрицательные сценарии, затем обновляется снимок. Для CI отсутствующий PostgreSQL DSN или неподдерживаемая файловая система являются **FAIL**, а не PASS/SKIP.

## Границы точности

Карта представляет собой статический исходный анализ: AST для Go и поиск характерных выражений в конфигурационных/скриптовых файлах. Включает и тестовые пути. Фрагмент SQL или слово `postgres` — **кандидат для просмотра**, не автоматически подтверждённый production blocker. Вызовы через рефлексию, динамическую конфигурацию и фактическое поведение в рантайме должны подтверждаться отдельно. Количество одинаково названных методов не служит сертификатом совместимости.

Версия 0.37.1 **не включает** SQLite HTTP Repository и **не снимает** запрет `single-node`. Продуктовый следующий шаг: реализовать HTTP repository и устранить найденные зависимости с обязательными security-parity и recovery тестами.
