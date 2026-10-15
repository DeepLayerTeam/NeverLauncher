# Документация NeverLauncher

Если документация расходится с кодом, проверяйте `schemas/openapi.yaml`, `VERSION`, исходники и результаты CI. **Поддержка целевой платформы в матрице не равна сертификату успешного запуска.**

## Начало работы

- [Быстрый старт](getting-started/quickstart.md) — требования, проверка дерева, сборка компонентов.
- [Production-развертывание](getting-started/production.md) — секреты, PostgreSQL/Redis, reverse proxy, первый запуск.
- [Локальная разработка](development/local-development.md) — инструменты и тесты.

## Управление платформой

- [Операции и резервные копии](administration/operations.md).
- [Пользователи, роли и сессии](administration/users-and-roles.md).
- [Провайдеры аутентификации](authentication/providers.md).
- [Профили, пакеты и запуск](clients/profiles-and-launch.md).
- [Матрица Minecraft и Java](clients/compatibility.md).
- [Скины и плащи](textures/skins-and-capes.md).
- [ServerBridge](servers/serverbridge.md).
- [NeverExtensions](extensions/overview.md) и [модель разрешений](extensions/security-and-lifecycle.md).

## Надёжность и справочники

- [Модель доверия](security/trust-model.md), [сертификация релизов](security/release-certification.md).
- [Миграции и обновление](migration/upgrade.md).
- [Параметры конфигурации](reference/configuration.md), [CLI](reference/cli.md), [HTTP API](reference/api.md).
- [Типовые проблемы](troubleshooting/common.md), [ошибки CI](troubleshooting/ci.md).

Корневые документы: [README](../README.md), [архитектура](../ARCHITECTURE.md), [вклад](../CONTRIBUTING.md), [поддержка](../SUPPORT.md), [план развития](../ROADMAP.md), [политика безопасности](../SECURITY.md).
