# Документация NeverLauncher

> **Один вход в документацию — разные маршруты для разных ролей.** Здесь собраны продуктовые материалы, руководства по внедрению, технические справочники и правила безопасного выпуска.

**Исходная версия:** [`1.0.0`](../VERSION) · **Выпуск:** кандидат, окончательная общедоступная сертификация не заявлена.

[Главная](../README.md) · [Продукт](product/README.md) · [Релизы](releases/README.md) · [Операторам](operator/README.md) · [Разработчикам](development/local-development.md)

---

## Выберите маршрут

| Роль | Первые шаги | Следующий материал |
| :--- | :--- | :--- |
| **Владелец проекта** | [Понимание продукта](product/README.md) | [Профили и доставка клиента](clients/profiles-and-launch.md) |
| **Игрок** | [Путь пользователя](product/journeys.md) | [Профили и запуск](clients/profiles-and-launch.md) |
| **Администратор** | [Управление проектом](administration/admin.md) | [Рабочая область выпуска](administration/release-workspace.md) |
| **Оператор** | [Установка](operator/installation.md) | [Обновление и откат](operator/upgrades.md) |
| **Разработчик** | [Быстрый старт](getting-started/quickstart.md) | [Локальная разработка](development/local-development.md) |
| **Ответственный за выпуск** | [Описание 1.0.0](releases/1.0.0.md) | [Проверки перед публикацией](releases/release-checklist.md) |

## Продукт

- [Обзор NeverLauncher](product/README.md) — кому нужна платформа, из чего она состоит и чего не обещает.
- [Возможности и границы](product/capabilities.md) — функциональные блоки, условия применения, ссылки на реализацию.
- [Основные сценарии](product/journeys.md) — пути владельца, игрока и оператора.
- [Совместимость](clients/compatibility.md) — версии Minecraft и загрузчики, правила подтверждения поддержки.
- [Скины и плащи](textures/skins-and-capes.md) — публикация и доставка пользовательских ресурсов.

## Релизы и надёжность

- [Релизный центр](releases/README.md) — статус версий, значение статусов, карта документов.
- [Что входит в 1.0.0](releases/1.0.0.md) — возможности версии и обязательные ограничения.
- [Путь от исходников до выпуска](releases/release-process.md) — подготовка, приёмка, подпись и публикация.
- [Контрольный список выпуска](releases/release-checklist.md) — проверяемые условия допуска.
- [История изменений](../CHANGELOG.md) — изменения по версиям.
- [Сертификация](security/release-certification.md) и [приёмка шести платформ](acceptance/supported-platform-ga-1.0.0.md) — первичные нормативные процедуры.

## Внедрение и эксплуатация

- [Быстрый старт](getting-started/quickstart.md) и [промышленное развёртывание](getting-started/production.md).
- [Руководство оператора](operator/README.md) — установка, резервное копирование, обновление и приёмка.
- [Управление пользователями и ролями](administration/users-and-roles.md).
- [Провайдеры аутентификации](authentication/providers.md).
- [ServerBridge](servers/serverbridge.md) и [расширения](extensions/overview.md).
- [Миграции](migration/upgrade.md), [восстановление](operator/backup-recovery.md), [диагностика](troubleshooting/common.md).

## Архитектура и справочники

- [Архитектура](../ARCHITECTURE.md), [модель доверия](security/trust-model.md).
- [Настройки](reference/configuration.md), [командная строка](reference/cli.md), [HTTP API](reference/api.md).
- [Разработка](../DEVELOPMENT.md), [правила участия](../CONTRIBUTING.md), [политика безопасности](../SECURITY.md) и [поддержка](../SUPPORT.md).

---

**Как читать заявления о готовности.** Наличие механизма или записи в матрице **не равно** сертифицированному результату. При расхождении описания с поведением реализации опирайтесь на точный коммит, [`VERSION`](../VERSION), [OpenAPI](../schemas/openapi.yaml), исходники и независимые результаты испытаний. Успешные тесты контрактов не заменяют нативные и игровые проверки.
