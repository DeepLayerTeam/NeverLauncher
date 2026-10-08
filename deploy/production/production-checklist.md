# Production-чеклист NeverLauncher

## Перед запуском

- [ ] Заполнен рабочий `.env`; значения `CHANGE_ME` отсутствуют.
- [ ] Установлен сильный `NEVERLAUNCHER_AUTH_TOKEN_SECRET`.
- [ ] `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` содержит merged NeverGuard политика схема 2.0 для текущей версии: точный Настольное приложение+Защита пары всех платформ; Windows fragment получен после Authenticode, macOS — после Разработчик ID подписание + notarization.
- [ ] `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON` заполнен точными SHA-256 релиз JAR из `BRIDGE_RELEASE_ALLOWLIST.json`; после публикации старый хеш удаляется из список разрешений только вместе с осознанным отзывом соответствующего ServerBridge релиз.
- [ ] Задан одноразовый `NEVERLAUNCHER_BOOTSTRAP_TOKEN` для новой установки и предусмотрено его удаление после инициализировать.
- [ ] Задан `NEVERLAUNCHER_REPOSITORY_DRIVER=postgres`.
- [ ] Задан `NEVERLAUNCHER_SQL_DRIVER=pgx`.
- [ ] Задан `NEVERLAUNCHER_DATABASE_DSN`.
- [ ] PostgreSQL доступен только backend-сервису.
- [ ] Redis защищён паролем и не опубликован на хост.
- [ ] Выбран хранилище драйвер: `local` или `s3`.
- [ ] Настроен HTTPS reverse прокси и корректный `NEVERLAUNCHER_PUBLIC_URL`.
- [ ] `NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` содержит только необходимые HTTPS источник и не содержит `*`.
- [ ] `NEVERLAUNCHER_TRUSTED_PROXY_CIDRS` содержит только доверенные внутренние сети.
- [ ] `NEVERLAUNCHER_BACKUP_ROOT` находится на отдельном от рабочего хранилище томе/каталоге.
- [ ] Выполнены `nl backup create`, `nl backup inspect`, `nl backup restore-dry-run` и тестовое восстановление в изолированном окружении.
- [ ] Для 0.13.0 `nl db migrate verify` подтверждает запечатанный `0018_device_trust_stabilization_01210`; пустая `0019` отсутствует.
- [ ] Официальный 0.13.0 комплект содержит `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json` для точный исходник фиксация и проходит `nl release publish-check`.
- [ ] При обновление с 0.12.9 старые API экземпляр остановлены; `nl db migrate apply` и `nl db migrate verify` успешно применили/проверили `0018_device_trust_stabilization_01210` до запуска 0.12.10 API.
- [ ] При обновление с 0.13.9 старые API экземпляр остановлены; `nl db migrate apply`/`verify` успешно довели схема до запечатанный `0020_guard_migration_compatibility_stabilization_01310`, а частичный Защита снимки отсутствуют.
- [ ] Для 0.19.2 ServerBridge 3 собраны все 11 соответствующий платформе JAR; `SERVERBRIDGE3_CERTIFICATION.json` имеет состояние `certified`, точная версия `0.19.2`, protocolVersion `3`, содержит `BridgeRuntimeIdentity`/обнаружение среда выполнения, совпадает с `BRIDGE_RELEASE_ALLOWLIST.json`, а `nl release publish-check` повторно проверяет hashes/sizes каждого JAR. `nl db migrate verify` подтверждает `0033_serverbridge_runtime_identity_0192`; после сигнал состояния узел диагностика содержит подписанный `runtimeId`, среда выполнения эпоха и Minecraft/Java/loader/brand метаданные.
- [ ] Для 0.19.3 ServerBridge 3 телеметрия согласование содержит `telemetry.server-v1`; `nl db migrate verify` подтверждает `0034_serverbridge_telemetry_0193`; сигнал состояния сохраняет привязанный к среде выполнения последний sample/history, а сертификация релиза подтверждает `BridgeTelemetrySampler`/`BridgeTickSampler` во всех 11 JAR. Проверен ограниченный хранение: примерно 4096 samples/node и purge старше 7 дней.
- [ ] Для 0.19.4 ServerBridge 3 событие поток согласовывать возможность `events.ordered-stream-v1`; миграция `0035_serverbridge_event_stream_0194` применена; событие/ACK курсор и `audit_events` пишутся транзакционно, а reconnect/reload подтверждён долговременный журнал + идемпотентный resend.
- [ ] Для 0.14.10 `nl db migrate verify` подтверждает запечатанный `0030_serverbridge_migration_stabilization_01410`; точный 0.14.9→0.14.10 репетиция сохраняет узел идентичность состояние, удаляет истёкший одноразовые значения, seal-ит устаревший топология, а среда выполнения обслуживание использует ограниченный `FOR UPDATE SKIP LOCKED` пакеты и хранение очистка.
- [ ] Для 0.14.9 `nl db migrate verify` подтверждает запечатанный `0029_serverbridge_public_matrix_ha_hardening_0149`; `/ready` видит ServerBridge HA снимок, Redis ограничение частоты работает отказ с блокировкой, публичная матрица показывает 11 поддерживаемый цели, устаревший топология не считается активный, а multi-экземпляр одноразовое значение replay/maintenance E2E проходит.
- [ ] Для 0.14.8 `nl db migrate verify` подтверждает запечатанный `0028_zero_patch_topology_handoff_0148`; proxy/backend узлы обновлены до 0.14.8, Minecraft/proxy конфигурация не патчатся NeverLauncher-ом, прокси→серверная часть передача проходит один раз, повторное воспроизведение отклоняется, а `GET /api/v1/server-bridge/topology` показывает среда выполнения-learned edges из PostgreSQL.
- [ ] Для 0.14.7 `nl db migrate verify` подтверждает запечатанный `0027_forge_neoforge_server_bridge_0147`; Forge/NeoForge 1.21.1 узлы используют соответствующие сервер-только мост JAR, канонический `kind=forge`/`kind=neoforge`, отдельные Ed25519 идентичности и отдельные `forgeSha256`/`neoforgeSha256`.
- [ ] Для 0.14.6 `nl db migrate verify` подтверждает запечатанный `0026_fabric_server_bridge_0146`; Fabric 1.21.1 сервер использует сервер-только `neverlauncher-fabric-bridge-0.14.6.jar` + Fabric API, зарегистрирован как `kind=fabric`, а релиз список разрешений содержит отдельный `fabricSha256`.
- [ ] Для 0.14.5 `nl db migrate verify` подтверждает запечатанный `0025_proxy_family_0145`; Velocity/BungeeCord/Waterfall используют отдельные соответствующий платформе JAR/узел идентичности, а релиз список разрешений содержит отдельные SHA-256 всех прокси и Bukkit-семейство артефакты.
- [ ] Для 0.14.4 `nl db migrate verify` подтверждает запечатанный `0024_bukkit_family_0144`; установлены соответствующий платформе Bukkit/Spigot/Paper/Purpur/Folia JAR, Folia дескриптор содержит `folia-supported: true`, а релиз список разрешений содержит отдельные SHA-256 всех семейство артефакты.
- [ ] Для 0.14.3 `nl db migrate verify` подтверждает запечатанный `0023_one_time_join_tickets_0143`; устаревший активный подключается сброшены, новый ServerBridge подключение имеет `ticketVersion=2` и идентичность привязка, первый подписанный использование создаёт сохранённый доказательство и повторное воспроизведение отклоняется; Yggdrasil `/hasJoined` одноразовое использование.
- [ ] Для 0.14.2 `nl db migrate verify` подтверждает запечатанный `0022_serverbridge_crypto_node_identities_0142`; 0.14.1 ServerBridge узлы прошли Ed25519 `rotate-identity` регистрация, закрытый ключи остаются только на узлы, heartbeat/validate работают с подписанный запрос заголовки и одноразовое значение защита от повторного воспроизведения.
- [ ] `api-volume-init` завершился успешно; именованный тома storage/backups принадлежат UID/GID `10001:10001`.

## После запуска

- [ ] `GET /health` возвращает версию из корневого `VERSION`.
- [ ] `GET /ready` возвращает готовность и не скрывает ошибки миграций/Redis.
- [ ] `GET /api/v1/status` отвечает через канонический API v1.
- [ ] Исторические `/api/v2`–`/api/v5` не доступны.
- [ ] Администратор вход создаёт серверную сессию и Bearer токен доступа.
- [ ] Клиент пакет publish/consume конвейер проходит быстрая проверка.
- [ ] ServerBridge Velocity/BungeeCord/Waterfall/Spigot/Paper/Purpur/Folia/Fabric/Forge/NeoForge проходит healthcheck; Bukkit артефакт проходит сборка/API контроль совместимости и отказ с блокировкой платформа обнаружение.

## Перед комплект релиза

- [ ] `NEVERLAUNCHER_PREFLIGHT_STRICT=1./scripts/release/preflight.sh` завершается успешно без пропущенных production-проверок.
- [ ] `nl release doctor` возвращает `repository-policy-ready` без ошибка проверяет; этот статус не заменяет строгий предварительная проверка.
- [ ] `python3 scripts/version/manage.py check` подтверждает согласованность обязательных версия метаданные с `VERSION`.
- [ ] CLI не содержит исторических `schemaVersion` 4.x–8.x.
- [ ] `CHANGELOG.md` обновлён.
- [ ] Для 0.15.2+ Windows рабочий доставка содержит x64 и ARM64 CLI/Desktop/NeverGuard/NeverRuntime, `WINDOWS_SIGNING_EVIDENCE.json`, `WINDOWS_PACKAGE_MANIFEST_X64.json`, `WINDOWS_PACKAGE_MANIFEST_ARM64.json` и `GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json`; `nl delivery verify-windows --production` проходит с реальным Authenticode + RFC3161 метка времени.
- [ ] Для 0.15.3+ Linux рабочий доставка содержит нативный x64 и ARM64 CLI/API/Desktop/NeverGuard/NeverRuntime, `LINUX_PACKAGE_MANIFEST_X64.json`, `LINUX_PACKAGE_MANIFEST_ARM64.json`, `LINUX_PRODUCTION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json`; `nl delivery verify-linux` проходит и оба tar.gz связаны с `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.4+ macOS рабочий доставка содержит отдельные облегчённый x64 и ARM64 CLI/Desktop/NeverGuard/NeverRuntime, `MACOS_PACKAGE_MANIFEST_X64.json`, `MACOS_PACKAGE_MANIFEST_ARM64.json`, `MACOS_NOTARIZATION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json`; `nl delivery verify-macos --production` подтверждает Разработчик ID, Принят notarization, stapled билет, Gatekeeper и привязка к `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.5+ Управляемый JRE доставка содержит точные Temurin 21 JRE архив для Windows/Linux/macOS x64+ARM64, `MANAGED_JRE_MANIFEST.json` и `MANAGED_JRE_EVIDENCE.json`; `nl delivery verify-jre` подтверждает поставщик SHA-256/size, архитектуру `bin/java` и привязка всех восьми артефакты к `DELIVERY_MANIFEST.json`.
- [ ] Для 0.15.6+ `nl update self-test` проходит на целевой платформе, `client install/update/package-apply` используют Единый Транзакционный Обновлятор Ядро, а `nl release publish-check` повторно выполняет commit/rollback self-тест перед публикацией.
- [ ] Для 0.15.7+ Настольное приложение self-обновление использует внешний `nl update components` вспомогательный модуль: пакет закреплять по SHA-256, NeverGuard завершение, единая Desktop/Guard/Runtime транзакция, macOS whole-app атомарный swap, восстановление после сбоя и автоматический откат; `nl update component-self-test` проходит на Linux x64/ARM64, Windows и macOS.
- [ ] Для 0.15.9+ комплект содержит `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` с ровно Windows/Linux/macOS × x64/ARM64; каждый цель привязан к точный CLI/Desktop/Guard/Runtime/package/Managed JRE (Linux также API), матрица входит в подписанный релиз граница, а после публикации `nl delivery public-e2e` успешно скачивает публичные байты и создаёт `PUBLIC_DELIVERY_E2E_REPORT.json`.
- [ ] Для 0.15.10+ выполнен `nl update migrate-state --root <install>` (или подтверждена автоматическая миграция): устаревший macOS компонент состояние отсутствует, канонический `.neverlauncher/component-update-state.json` валиден, неполный транзакция восстановлены, конечный staging/backup полезная нагрузка очищены; `nl update stabilization-self-test` проходит.
- [ ] Релиз доверие состояние для 0.15.10+ хранится вне комплект, успешно мигрирован в схема 2.1, содержит `highestReleaseManifestSha256`/`stateRevision`, а `nl release verify` использует сериализованный `<trust-state>.lock` и отклоняет другой манифест для уже принятой той же версии.
- [ ] Для 0.15.11+ комплект содержит `PRODUCTION_RELEASE_CANDIDATE.json`; `sourceCommit` совпадает с Git `HEAD`, Compatibility/Device Trust/Guard CI сертификация и `PROVENANCE.json`; `nl release candidate-verify <bundle>` проходит до `release sign`, а `release publish-check` повторно подтверждает рабочий Authenticode/notarization и точный группа после подписи.
- [ ] Для 0.16.0+ комплект содержит `PRODUCTION_DELIVERY_RELEASE.json`; `nl release production-verify <bundle>` подтверждает стабильный канал, точный исходник фиксация, six-цель якоря и версия HTTPS публичный источник, `RELEASE_MANIFEST.json` содержит совпадающий `productionDeliveryReleaseSha256`, а Публичный Доставка Матрица публикует GA сертификат как управление для после публикации E2E.
- [ ] Закрытый Ed25519 релиз ключ хранится вне репозитория; доверенный открытый ключ распространяется отдельным доверенным каналом.
- [ ] `scripts/release/build-release.sh` собрал реальные CLI/API/Admin/Desktop/NeverRuntime/Velocity/BungeeCord/Waterfall/Bukkit/Spigot/Paper/Purpur/Folia артефакты и исходник архив прошёл секрет scan.
- [ ] Подготовлены `RELEASE_MANIFEST.json`, `SHA256SUMS`, `SHA256SUMS.sig`, `SBOM.spdx.json` и `PROVENANCE.json`.
- [ ] Для Minecraft Совместимость Релиз и новее в комплект присутствуют `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json`, `COMPATIBILITY_CERTIFICATION.json`, привязанные к точный исходник фиксация.
- [ ] Для 0.17.11+ комплект также содержит `LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json`: 292/292 цели, полный свидетельство корень, family/platform/Java покрытие и все RC инварианты валидны; его SHA-256 совпадает с `RELEASE_MANIFEST.json` и входит в подписанный `SHA256SUMS`.
- [ ] Для 0.18.0+ загрузчик сертификат имеет `status=ga-certified`, `runtimeSupportEntries=163`, точный устаревший Forge `[1.7.10, 1.12.2]`; `RELEASE_MANIFEST.json` содержит `loaderCompatibilityGA=true` и совпадающий `loaderCompatibilityGASupportSha256`, а `nl release publish-check` пересчитывает GA политика привязка.
- [ ] Для 0.18.12+ комплект содержит точный-фиксация `WINDOWS_ADVERSARIAL_CERTIFICATE.json` и `WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json`; `nl release windows-protection-verify` и `publish-check` пересчитывают агрессивный-профиль Windows x64/ARM64 артефакт граница, а `RELEASE_MANIFEST.json` фиксирует SHA-256 обоих сертификатов.
- [ ] Для 0.19.0+ комплект содержит `WINDOWS_PROTECTION_GA_CERTIFICATE.json`; `nl release windows-protection-ga-verify` подтверждает user-mode/aggressive/fail-closed граница, отсутствие `.sys` полезная нагрузка в Windows пакеты и привязка к RC/adversarial точный байты.
- [ ] Для 0.13.9+ в комплект присутствуют `GUARD_CI_TARGETS.json`, `GUARD_CI_MATRIX.json`, `GUARD_CI_CERTIFICATION.json`; матрица содержит PASS Linux/Windows/macOS для точный commit/run, а комплект содержит именно сертифицированные платформа артефакты.
- [ ] Для 0.13.10+ каждый Защита цель результат дополнительно совпадает с агрегат матрица по `repository`; свидетельство из другого ответвление не принимается.
- [ ] `nl release verify <release-dir> --public-key <trusted-public-key>` проходит успешно и все `required=true` артефакты имеют `status=present`.
- [ ] `nl release publish-check <release-dir> --public-key <trusted-public-key>` проходит Совместимость + Доверие к устройству + Кроссплатформенный Защита сертификация контроли.

## ServerBridge 0.19.5 Управление API

- [ ] Настроен ключ подписи ServerBridge 0.19.5 Управление API, проверены назначения `serverbridge:control` / `serverbridge:console`, а для каждого Мост задан локальный консоль список разрешений.
- [ ] Control-команды проверены через нативный платформа APIs; выполнение OS shell/process по-прежнему отключено.
