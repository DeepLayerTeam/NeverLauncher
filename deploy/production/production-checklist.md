# Production-чеклист NeverLauncher 0.10.0-P3.2v4

## Перед запуском

- [ ] Заполнен production `.env`; значения `CHANGE_ME` отсутствуют.
- [ ] Установлен сильный `NEVERLAUNCHER_AUTH_TOKEN_SECRET`.
- [ ] Задан одноразовый `NEVERLAUNCHER_BOOTSTRAP_TOKEN` для новой установки и предусмотрено его удаление после bootstrap.
- [ ] Задан `NEVERLAUNCHER_REPOSITORY_DRIVER=postgres`.
- [ ] Задан `NEVERLAUNCHER_SQL_DRIVER=pgx`.
- [ ] Задан `NEVERLAUNCHER_DATABASE_DSN`.
- [ ] PostgreSQL доступен только backend-сервису.
- [ ] Redis защищён паролем и не опубликован на host.
- [ ] Выбран storage driver: `local` или `s3`.
- [ ] Настроен HTTPS reverse proxy и корректный `NEVERLAUNCHER_PUBLIC_URL`.
- [ ] `NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` содержит только необходимые HTTPS origin и не содержит `*`.
- [ ] `NEVERLAUNCHER_TRUSTED_PROXY_CIDRS` содержит только доверенные внутренние сети.
- [ ] `NEVERLAUNCHER_BACKUP_ROOT` находится на отдельном от рабочего storage томе/каталоге.
- [ ] Выполнены `nl backup create`, `nl backup inspect`, `nl backup restore-dry-run` и тестовое восстановление в изолированном окружении.
- [ ] `api-volume-init` завершился успешно; named volumes storage/backups принадлежат UID/GID `10001:10001`.

## После запуска

- [ ] `GET /health` возвращает версию `0.10.0-P3.2v4`.
- [ ] `GET /ready` возвращает готовность и не скрывает ошибки миграций/Redis.
- [ ] `GET /api/v1/status` отвечает через канонический API v1.
- [ ] Исторические `/api/v2`–`/api/v5` не доступны.
- [ ] Admin login создаёт серверную сессию и Bearer access token.
- [ ] Client package publish/consume pipeline проходит smoke-test.
- [ ] ServerBridge Velocity/Paper/Purpur проходит healthcheck.

## Перед release bundle

- [ ] `NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh` завершается успешно без пропущенных production-проверок.
- [ ] `nl release doctor` возвращает `repository-policy-ready` без failed checks; этот статус не заменяет строгий preflight.
- [ ] `VERSION`, CLI, API, Admin, Desktop, Tauri и ServerBridge согласованы с `0.10.0-P3.2v4`.
- [ ] CLI не содержит исторических `schemaVersion` 4.x–8.x.
- [ ] `CHANGELOG.md` обновлён.
- [ ] Private Ed25519 release key хранится вне репозитория; trusted public key распространяется отдельным доверенным каналом.
- [ ] `scripts/release/build-release.sh` собрал реальные CLI/API/Admin/Desktop/NeverRuntime/Velocity/Paper/Purpur artifacts и source archive прошёл secret scan.
- [ ] Подготовлены `RELEASE_MANIFEST.json`, `SHA256SUMS`, `SHA256SUMS.sig`, `SBOM.spdx.json` и `PROVENANCE.json`.
- [ ] `nl release verify <release-dir> --public-key <trusted-public-key>` проходит успешно и все `required=true` artifacts имеют `status=present`.
