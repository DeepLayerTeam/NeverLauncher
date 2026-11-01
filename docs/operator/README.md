# Руководство оператора NeverLauncher 0.45.13

**Это исполняемые процедуры для текущего исходного дерева, а не свидетельство успешной установки на вашем сервере.** Команды запускаются из корня репозитория, если не указано иное. Версию проверяйте по `VERSION`; перед production-операцией сверяйте точный commit и SHA-256 установленных файлов. Недоступность хоста, секретов, нативной подписи или исполняемой платформенной проверки означает `NOT RUN`, а не `PASS`.

## Маршруты оператора

1. [Установка и первый владелец](installation.md): Minimal/Standard/Network-HA, TLS, зависимости и контроль запуска.
2. [Резервное копирование и восстановление](backup-recovery.md): минимальная SQLite, Standard PostgreSQL, миры и Network-HA fencing.
3. [Обновление и откат](upgrades.md): изменения БД, API, CLI, Bridge, Desktop, Runtime, Guard и расширений.
4. [HA, инциденты и восстановление](ha-incidents.md): диагностический пакет, alerting, отказ инфраструктуры, RPO/RTO.
5. [Безопасность и релиз](security-delivery.md): secrets, сертификаты, подписанные пакеты, API/SDK и миграция Gravit.
6. [Контрольная ведомость второго оператора](operator-checklist.md): наблюдаемые условия приёмки.

### Запуск автоматической проверки

```sh
python3 scripts/operations/operator_accept_04513.py docs-check
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
```

`docs-check` проверяет локальные ссылки и существование используемых операционных скриптов; **не выполняет установку и не выдаёт сертификат**. Для проверки реально запущенного backend выполните команду `operator_accept_04513.py live` из [раздела установки](installation.md). Результат (`0600` JSON) содержит проверенные сервисы и состояние `/ready`, но не полный пользовательский цикл или проверки failover.

### Границы и роли

Minimal — один API с SQLite и локальными файлами; не распределяйте SQLite по NFS. Standard — PostgreSQL и локальные Docker volumes, SQLite-координатор, один API. Network-HA — PostgreSQL, Redis, внешнее S3 и два API/два workers; Compose на одном хосте **не является** multi-host HA. Оператор не должен одновременно поднимать прежний и восстановленный контур с одинаковыми подписывающими ключами, ServerBridge-узлами и игровыми мирами. Нужны отдельно проверенные TLS/DNS, бэкап секретов, тест входа прежнего владельца и запуск Minecraft.

Подробности продукта: [OpenAPI и SDK](../releases/0.45.12-api-sdk-freeze-candidate.md), [обзор политики выпуска](../operations/release-policy-0361.md), [проверки безопасности](../security/trust-model.md).
