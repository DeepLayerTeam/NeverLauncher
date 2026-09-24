# Production-чеклист NeverLauncher

## Перед запуском

- [ ] Заполнен production `.env`; значения `CHANGE_ME` отсутствуют.
- [ ] Установлен сильный `NEVERLAUNCHER_AUTH_TOKEN_SECRET`.
- [ ] `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` содержит merged NeverGuard policy schema 2.0 для текущей версии: exact Desktop+Guard pairs всех платформ; Windows fragment получен после Authenticode, macOS — после Developer ID signing + notarization.
- [ ] `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` заполнен точными SHA-256 release JAR из `BRIDGE_RELEASE_ALLOWLIST.json`; после публикации старый hash удаляется из allowlist только вместе с осознанным отзывом соответствующего ServerBridge release.
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
- [ ] Для 0.13.0 `nl db migrate verify` подтверждает sealed `0018_device_trust_stabilization_01210`; пустая `0019` отсутствует.
- [ ] Официальный 0.13.0 bundle содержит `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json` для exact source commit и проходит `nl release publish-check`.
- [ ] При upgrade с 0.12.9 старые API instance остановлены; `nl db migrate apply` и `nl db migrate verify` успешно применили/проверили `0018_device_trust_stabilization_01210` до запуска 0.12.10 API.
- [ ] При upgrade с 0.13.9 старые API instance остановлены; `nl db migrate apply`/`verify` успешно довели schema до sealed `0020_guard_migration_compatibility_stabilization_01310`, а partial Guard snapshots отсутствуют.
- [ ] Для 0.14.3 `nl db migrate verify` подтверждает sealed `0023_one_time_join_tickets_0143`; legacy active joins сброшены, новый ServerBridge join имеет `ticketVersion=2` и identity binding, первый signed redemption создаёт persisted proof и replay отклоняется; Yggdrasil `/hasJoined` consume-once.
- [ ] Для 0.14.2 `nl db migrate verify` подтверждает sealed `0022_serverbridge_crypto_node_identities_0142`; 0.14.1 ServerBridge nodes прошли Ed25519 `rotate-identity` enrollment, private keys остаются только на nodes, heartbeat/validate работают с signed request headers и nonce replay protection.
- [ ] `api-volume-init` завершился успешно; named volumes storage/backups принадлежат UID/GID `10001:10001`.

## После запуска

- [ ] `GET /health` возвращает версию из корневого `VERSION`.
- [ ] `GET /ready` возвращает готовность и не скрывает ошибки миграций/Redis.
- [ ] `GET /api/v1/status` отвечает через канонический API v1.
- [ ] Исторические `/api/v2`–`/api/v5` не доступны.
- [ ] Admin login создаёт серверную сессию и Bearer access token.
- [ ] Client package publish/consume pipeline проходит smoke-test.
- [ ] ServerBridge Velocity/Paper/Purpur проходит healthcheck.

## Перед release bundle

- [ ] `NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh` завершается успешно без пропущенных production-проверок.
- [ ] `nl release doctor` возвращает `repository-policy-ready` без failed checks; этот статус не заменяет строгий preflight.
- [ ] `python3 scripts/version/manage.py check` подтверждает согласованность обязательных version metadata с `VERSION`.
- [ ] CLI не содержит исторических `schemaVersion` 4.x–8.x.
- [ ] `CHANGELOG.md` обновлён.
- [ ] Private Ed25519 release key хранится вне репозитория; trusted public key распространяется отдельным доверенным каналом.
- [ ] `scripts/release/build-release.sh` собрал реальные CLI/API/Admin/Desktop/NeverRuntime/Velocity/Paper/Purpur artifacts и source archive прошёл secret scan.
- [ ] Подготовлены `RELEASE_MANIFEST.json`, `SHA256SUMS`, `SHA256SUMS.sig`, `SBOM.spdx.json` и `PROVENANCE.json`.
- [ ] Для Minecraft Compatibility Release и новее в bundle присутствуют `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json`, `COMPATIBILITY_CERTIFICATION.json`, привязанные к exact source commit.
- [ ] Для 0.13.9+ в bundle присутствуют `GUARD_CI_TARGETS.json`, `GUARD_CI_MATRIX.json`, `GUARD_CI_CERTIFICATION.json`; matrix содержит PASS Linux/Windows/macOS для exact commit/run, а bundle содержит именно сертифицированные platform artifacts.
- [ ] Для 0.13.10+ каждый Guard target result дополнительно совпадает с aggregate matrix по `repository`; evidence из другого fork не принимается.
- [ ] `nl release verify <release-dir> --public-key <trusted-public-key>` проходит успешно и все `required=true` artifacts имеют `status=present`.
- [ ] `nl release publish-check <release-dir> --public-key <trusted-public-key>` проходит Compatibility + Device Trust + Cross-platform Guard certification gates.
