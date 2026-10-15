# NeverLauncher

**NeverLauncher** — открытая платформа управления и доставки Minecraft-клиентов: серверное API, веб-панель, настольный лаунчер, CLI, собственный runtime, NeverGuard, ServerBridge и NeverExtensions. Репозиторий содержит код продукта, инфраструктуру развертывания и тестовые матрицы; это не готовый Minecraft-сервер или дистрибутив игры.

- **Текущая версия исходников:** [`VERSION`](VERSION). Другие модули синхронизируются с этим файлом; не изменяйте версию вручную в отдельных пакетах.
- **Лицензия:** [Apache License 2.0](LICENSE), дополнительные сведения — [NOTICE](NOTICE).
- **Исходники:** https://github.com/DeepLayerTeam/NeverLauncher
- **Совместимость:** [COMPATIBILITY.md](COMPATIBILITY.md), [матрица целевых сочетаний](compatibility/targets.json). Запись в матрице не означает успешную сертификацию.
- **Обратная связь:** [задачи](https://github.com/DeepLayerTeam/NeverLauncher/issues), [обсуждения](https://github.com/DeepLayerTeam/NeverLauncher/discussions); сообщения об уязвимостях — через [SECURITY.md](SECURITY.md).

## Состав продукта

| Компонент | Расположение | Назначение |
| --- | --- | --- |
| Backend API | `services/api/` | Авторизация, пользователи, проекты, профили, каналы, пакеты, хранение, ServerBridge, расширения и эксплуатационные операции |
| Admin | `apps/admin/` | Веб-интерфейс управления |
| Desktop | `apps/desktop/` | React + Tauri: конфигурация, проверка файлов и запуск клиентов |
| CLI `nl` | `cli/` | Установка, администрирование, манифесты, диагностика, сборка и проверка релизов |
| NeverRuntime / NeverGuard | `runtime/` | Minecraft/JRE runtime, загрузки, контроль целостности и защитные механизмы |
| ServerBridge | `plugins/`, `serverbridge/` | Интеграции Minecraft-серверов и прокси, управление узлами |
| NeverExtensions | `neverextensions/`, `sdk/`, `examples/extensions/` | Расширения и SDK |
| Контракты и проверки | `schemas/`, `compatibility/`, `device-trust/`, `e2e/`, `scripts/` | OpenAPI, проверка версий, матрицы и выпускные проверки |

## Быстрый старт для разработчиков

Установите Go 1.23 (как в CI), Node.js/npm, Python 3, Rust/Cargo; для мостов также JDK и Gradle. Для реального API необходимы PostgreSQL и, в предусмотренных сценариях, Redis. **Не используйте пример `.env` для промышленной эксплуатации.**

```bash
# Из корня репозитория: проверка версии и OpenAPI
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py

# Отдельные Go-модули
(cd services/api && go test ./...)
(cd cli && go test ./...)

# Веб-интерфейсы
(cd apps/admin && npm ci && npm run build)
(cd apps/desktop && npm ci && npm run build)
```

Команда `npm run build` для Desktop собирает веб-часть; нативная упаковка Tauri требует соответствующего toolchain и отдельной команды. Полный цикл описан в [документации для разработчиков](DEVELOPMENT.md).

Для запуска production-окружения **необходимо предварительно настроить секреты, подписи, доверенные политики и TLS**: [руководство по развертыванию](docs/getting-started/production.md). Для первого знакомства используйте [пошаговое руководство](docs/getting-started/quickstart.md).

## Документация

Начните с [индекса документации](docs/README.md). Полезные разделы: [архитектура](ARCHITECTURE.md), [авторизация](docs/authentication/providers.md), [клиенты](docs/clients/profiles-and-launch.md), [ServerBridge](docs/servers/serverbridge.md), [NeverExtensions](docs/extensions/overview.md), [безопасность](docs/security/trust-model.md), [CLI](docs/reference/cli.md), [API](docs/reference/api.md) и [диагностика](docs/troubleshooting/common.md).

## Проверки и ограничения

Процессы GitHub Actions включают тесты Go, Rust, TypeScript, статические контракты и платформенные матрицы. **Успешная проверка структуры не эквивалентна реальному запуску Minecraft**. Для выпуска изучайте сертификаты точного коммита и результаты [предрелизные проверки](docs/security/release-certification.md). Некоторые пользовательские сценарии (например, полноценный интерфейс выбора дополнительных модов или официальную проверку владения Minecraft) могут требовать дополнительной реализации и проверки — наличие отдельных API не подтверждает завершённый сквозной сценарий.

## Участие

Перед изменением кода прочитайте [CONTRIBUTING.md](CONTRIBUTING.md), [DEVELOPMENT.md](DEVELOPMENT.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Не помещайте секреты, персональные данные или неподписанные артефакты релиза в pull request.
