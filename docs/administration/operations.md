# Эксплуатация и операции

## Что контролировать

- Доступность `/health`, `/ready`, backend/Redis/PostgreSQL и состояние миграций.
- Заполнение storage, очереди задач/событий расширений и статус ServerBridge-узлов.
- Ошибки удостоверений, подозрительные сессии, аудит действий администратора и выпуска релизов.
- Текущий version alignment, сертификаты точного коммита и сроки действия ключей/сертификатов.

## Управление через CLI

CLI поддерживает `nl operations status|readiness|diagnostics|diagnostics-bundle`, `nl adminops ...`, `nl backup ...`, `nl db ...`; для backend-сценариев указывайте `--backend <url>` и авторизованный токен. Точный перечень команд — `cli/cmd/neverlauncher/main.go` и [справочник](../reference/cli.md).

## Резервные копии

Планируйте согласованный снимок PostgreSQL и файлового storage, проверяйте тестовое восстановление и совместимость версий миграций. `nl backup create|inspect|restore-dry-run|restore` реализует отдельные операции, но **прогон dry-run не заменяет тест реального восстановления**. Храните backups отдельно от runtime и защищайте от удаления скомпрометированным приложением.

## Службы

Docker Compose: `deploy/production/docker-compose.yml`; systemd: `deploy/systemd/neverlauncher-api.service`; nginx: `deploy/production/nginx.conf`. Настройка reverse proxy и TLS зависит от инфраструктуры. Разрешайте сервисные порты минимальному набору сетей и проверяйте готовность API до подключения Desktop.

См. [production](../getting-started/production.md) и [upgrades](../migration/upgrade.md).
