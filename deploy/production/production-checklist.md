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
- [ ] Для 0.15.0 ServerBridge 2 собраны все 11 platform-matched JAR; `SERVERBRIDGE2_CERTIFICATION.json` имеет status `certified`, exact version `0.15.0`, совпадает с `BRIDGE_RELEASE_ALLOWLIST.json`, а `nl release publish-check` повторно проверяет hashes/sizes каждого JAR.
- [ ] Для 0.14.10 `nl db migrate verify` подтверждает sealed `0030_serverbridge_migration_stabilization_01410`; exact 0.14.9→0.14.10 rehearsal сохраняет node identity state, удаляет expired nonces, seal-ит stale topology, а runtime maintenance использует bounded `FOR UPDATE SKIP LOCKED` batches и retention cleanup.
- [ ] Для 0.14.9 `nl db migrate verify` подтверждает sealed `0029_serverbridge_public_matrix_ha_hardening_0149`; `/ready` видит ServerBridge HA snapshot, Redis rate limit работает fail-closed, public matrix показывает 11 supported targets, stale topology не считается active, а multi-instance nonce replay/maintenance E2E проходит.
- [ ] Для 0.14.8 `nl db migrate verify` подтверждает sealed `0028_zero_patch_topology_handoff_0148`; proxy/backend nodes обновлены до 0.14.8, Minecraft/proxy configs не патчатся NeverLauncher-ом, proxy→backend handoff проходит один раз, replay отклоняется, а `GET /api/v1/server-bridge/topology` показывает runtime-learned edges из PostgreSQL.
- [ ] Для 0.14.7 `nl db migrate verify` подтверждает sealed `0027_forge_neoforge_server_bridge_0147`; Forge/NeoForge 1.21.1 nodes используют соответствующие server-only bridge JAR, canonical `kind=forge`/`kind=neoforge`, отдельные Ed25519 identities и отдельные `forgeSha256`/`neoforgeSha256`.
- [ ] Для 0.14.6 `nl db migrate verify` подтверждает sealed `0026_fabric_server_bridge_0146`; Fabric 1.21.1 server использует server-only `neverlauncher-fabric-bridge-0.14.6.jar` + Fabric API, зарегистрирован как `kind=fabric`, а release allowlist содержит отдельный `fabricSha256`.
- [ ] Для 0.14.5 `nl db migrate verify` подтверждает sealed `0025_proxy_family_0145`; Velocity/BungeeCord/Waterfall используют отдельные platform-matched JAR/node identities, а release allowlist содержит отдельные SHA-256 всех proxy и Bukkit-family artifacts.
- [ ] Для 0.14.4 `nl db migrate verify` подтверждает sealed `0024_bukkit_family_0144`; установлены platform-matched Bukkit/Spigot/Paper/Purpur/Folia JAR, Folia descriptor содержит `folia-supported: true`, а release allowlist содержит отдельные SHA-256 всех family artifacts.
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
- [ ] ServerBridge Velocity/BungeeCord/Waterfall/Spigot/Paper/Purpur/Folia/Fabric/Forge/NeoForge проходит healthcheck; Bukkit artifact проходит build/API compatibility gate и fail-closed platform detection.

## Перед release bundle

- [ ] `NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh` завершается успешно без пропущенных production-проверок.
- [ ] `nl release doctor` возвращает `repository-policy-ready` без failed checks; этот статус не заменяет строгий preflight.
- [ ] `python3 scripts/version/manage.py check` подтверждает согласованность обязательных version metadata с `VERSION`.
- [ ] CLI не содержит исторических `schemaVersion` 4.x–8.x.
- [ ] `CHANGELOG.md` обновлён.
- [ ] Для 0.15.2+ Windows production delivery содержит x64 и ARM64 CLI/Desktop/NeverGuard/NeverRuntime, `WINDOWS_SIGNING_EVIDENCE.json`, `WINDOWS_PACKAGE_MANIFEST_X64.json`, `WINDOWS_PACKAGE_MANIFEST_ARM64.json` и `GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json`; `nl delivery verify-windows --production` проходит с реальным Authenticode + RFC3161 timestamp.
- [ ] Для 0.15.3+ Linux production delivery содержит native x64 и ARM64 CLI/API/Desktop/NeverGuard/NeverRuntime, `LINUX_PACKAGE_MANIFEST_X64.json`, `LINUX_PACKAGE_MANIFEST_ARM64.json`, `LINUX_PRODUCTION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json`; `nl delivery verify-linux` проходит и оба tar.gz связаны с `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.4+ macOS production delivery содержит отдельные thin x64 и ARM64 CLI/Desktop/NeverGuard/NeverRuntime, `MACOS_PACKAGE_MANIFEST_X64.json`, `MACOS_PACKAGE_MANIFEST_ARM64.json`, `MACOS_NOTARIZATION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json`; `nl delivery verify-macos --production` подтверждает Developer ID, Accepted notarization, stapled ticket, Gatekeeper и binding к `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.5+ Managed JRE delivery содержит точные Temurin 21 JRE archive для Windows/Linux/macOS x64+ARM64, `MANAGED_JRE_MANIFEST.json` и `MANAGED_JRE_EVIDENCE.json`; `nl delivery verify-jre` подтверждает vendor SHA-256/size, архитектуру `bin/java` и binding всех восьми artifacts к `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.6+ `nl update self-test` проходит на целевой платформе, `client install/update/package-apply` используют Unified Transactional Updater Core, а `nl release publish-check` повторно выполняет commit/rollback self-test перед публикацией.
- [ ] Для 0.15.7+ Desktop self-update использует внешний `nl update components` helper: package pin по SHA-256, NeverGuard shutdown, единая Desktop/Guard/Runtime transaction, macOS whole-app atomic swap, crash recovery и automatic rollback; `nl update component-self-test` проходит на Linux x64/ARM64, Windows и macOS.
- [ ] Для 0.15.9+ bundle содержит `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` с ровно Windows/Linux/macOS × x64/ARM64; каждый target привязан к exact CLI/Desktop/Guard/Runtime/package/Managed JRE (Linux также API), matrix входит в signed release boundary, а после публикации `nl delivery public-e2e` успешно скачивает публичные bytes и создаёт `PUBLIC_DELIVERY_E2E_REPORT.json`.
- [ ] Для 0.15.10+ выполнен `nl update migrate-state --root <install>` (или подтверждена автоматическая migration): legacy macOS component state отсутствует, canonical `.neverlauncher/component-update-state.json` валиден, incomplete transaction восстановлены, terminal staging/backup payload очищены; `nl update stabilization-self-test` проходит.
- [ ] Release trust state для 0.15.10+ хранится вне bundle, успешно мигрирован в schema 2.1, содержит `highestReleaseManifestSha256`/`stateRevision`, а `nl release verify` использует serialized `<trust-state>.lock` и отклоняет другой manifest для уже принятой той же версии.
- [ ] Private Ed25519 release key хранится вне репозитория; trusted public key распространяется отдельным доверенным каналом.
- [ ] `scripts/release/build-release.sh` собрал реальные CLI/API/Admin/Desktop/NeverRuntime/Velocity/BungeeCord/Waterfall/Bukkit/Spigot/Paper/Purpur/Folia artifacts и source archive прошёл secret scan.
- [ ] Подготовлены `RELEASE_MANIFEST.json`, `SHA256SUMS`, `SHA256SUMS.sig`, `SBOM.spdx.json` и `PROVENANCE.json`.
- [ ] Для Minecraft Compatibility Release и новее в bundle присутствуют `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json`, `COMPATIBILITY_CERTIFICATION.json`, привязанные к exact source commit.
- [ ] Для 0.13.9+ в bundle присутствуют `GUARD_CI_TARGETS.json`, `GUARD_CI_MATRIX.json`, `GUARD_CI_CERTIFICATION.json`; matrix содержит PASS Linux/Windows/macOS для exact commit/run, а bundle содержит именно сертифицированные platform artifacts.
- [ ] Для 0.13.10+ каждый Guard target result дополнительно совпадает с aggregate matrix по `repository`; evidence из другого fork не принимается.
- [ ] `nl release verify <release-dir> --public-key <trusted-public-key>` проходит успешно и все `required=true` artifacts имеют `status=present`.
- [ ] `nl release publish-check <release-dir> --public-key <trusted-public-key>` проходит Compatibility + Device Trust + Cross-platform Guard certification gates.
