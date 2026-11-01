# Production deployment: действующий операторский путь

Текущая версия продукта определяется файлом `VERSION`. Установка требует реальной конфигурации, подтверждённых Guard/Bridge-политик, доверенного TLS и независимого хранилища ключей. Наличие скрипта или конфигурационного файла **не** является доказательством готовой установки.

Основной исполняемый runbook: [установка Minimal/Standard/Network-HA](../operator/installation.md). В нём приведены **реальные** вызовы `scripts/install/minimal-install.py` и `scripts/install/production-deploy.py`, первичное создание администратора через backend и отдельный read-only операторский probe `scripts/operations/operator_accept_04513.py`.

Операции после установки: [резервирование](../operator/backup-recovery.md), [обновления/откат](../operator/upgrades.md), [HA/инциденты](../operator/ha-incidents.md), [политика подписей](../operator/security-delivery.md) и [ведомость второго оператора](../operator/operator-checklist.md).

**Не следует использовать** только `scripts/install/production-setup.sh` как установщик: это предварительный отчёт. Проверенный рабочий запуск Standard использует `production-deploy.py compose check/up` и затем `compose first-admin`. Для Network-HA выполняется отдельная одноразовая миграция БД и запуск двух API/двух workers после проверки внешнего S3. Никогда не сохраняйте вывод `docker compose config` с секретами в общедоступный CI artifact.

Статус `docs-check` означает только проверку файлов; `live` подтверждает настоящее состояние процессов и `/ready`, а не успешный backup/restore, игровую авторизацию или переживание отказа физического хоста. Реальную приёмку следует записывать с SHA-256 и подтверждениями второго оператора.
