# Политика безопасности NeverLauncher

NeverLauncher использует модель безопасности, в которой критичные решения принимаются на стороне Backend API и ServerBridge, а Desktop Launcher не считается доверенной границей.

## Auth Federation 0.12 boundary

В `0.12.0` единственной authentication boundary является Federation Core: connector проверяет external proof, затем `(provider, subject)` разрешается в canonical Never user и только после этого NeverLauncher выпускает собственную session. Local password provider проходит тот же Connector SDK conformance gate. Generic explicit linking требует одновременно действующую Never session и завершённый browser-provider proof; совпадение email никогда не считается proof.

Migration `0011_auth_federation_release_0120` закрепляет local identity invariant на уровне PostgreSQL: password-capable user обязан иметь `provider=local, subject=user.id`. Bootstrap/password-reset пути обновлены транзакционно, поэтому invariant не обходится прямой записью в `users`. Runtime provider health доступен через административный federation status; production readiness не считается успешной, если не осталось ни одного здорового auth provider.
Выдача Never session не имеет права создавать identity. В частности, passwordless WebAuthn является authentication method/origin (`provider=passkey`), а не доказательством существования local-password identity; external-only пользователь с passkey не получает фиктивную `local` identity.

## Device Trust / device keys 0.12.2

Поле `deviceId` из login/session metadata не является доказательством устройства. Trusted device создаётся только после Ed25519 proof-of-possession: Backend выдаёт одноразовый persistent challenge, привязанный к canonical user, device id, purpose и Never session; официальный Desktop подписывает payload ключом, private seed которого находится только в native OS secure storage.

Desktop key namespace строится по `Backend + canonical user id`, а не email. Windows использует Credential Manager, macOS Keychain, Linux Secret Service через native keyring backend. Plaintext/file/localStorage fallback запрещён; React не получает private seed и может запросить только public metadata или подпись конкретного bounded challenge payload. Временные seed/serialized secret buffers zeroize перед освобождением.

OS secure storage само по себе не является hardware attestation. `0.12.2` сохраняет assurance `proof-of-possession`; hardware-bound assurance будет отдельным trust level только после проверяемой TPM/Secure Enclave/Windows Hello/аналогичной attestation.

В `trusted_devices` хранится только public key и SHA-256 fingerprint. Private device key не должен передаваться Backend или попадать в логи. Assurance этой версии называется `proof-of-possession`; NeverLauncher не заявляет hardware-bound identity до появления отдельной TPM/Secure Enclave/OS secure-storage и attestation проверки.

`device_challenges` single-use и расходуются атомарно; replay/expired challenge отклоняется. После успешного proof session получает `trusted_device_id/device_trust_state/device_verified_at`, а новый access JWT — `device_id/device_trust/device_verified_at`. Revoke registry device отзывает все связанные Never sessions и refresh-token families и переводит session risk в `compromised`.

Административный revoke устройства требует свежую phishing-resistant authentication. Device registry не заменяет WebAuthn user authentication: passkey доказывает пользователя/RP ceremony, device key доказывает владение конкретной зарегистрированной installation/device identity.

## Federated provider credentials

С `0.11.10` migration history считается частью security boundary. Production upgrade должен выполняться через `nl db migrate apply` и завершаться `nl db migrate verify`. Unknown/future migration, checksum drift или незапечатанный checksum блокируют verify; apply не продолжает работу при неизвестной migration или несовпадающем checksum. Migration `0010` также fail-closed проверяет согласованность auth sessions, refresh-token families/tokens и provider credentials до установки новых relational constraints.

Federation security regressions входят в release gate: HTTP HMAC/replay/SSRF, OIDC issuer/audience, Microsoft tenant/key issuer, WebAuthn origin/challenge replay, SQL TLS/read-only/disabled account и refresh-family replay выполняются как тесты, а не как документационные promises. Strict preflight дополнительно требует multi-instance PostgreSQL E2E.

Начиная с 0.11.6 внешние refresh credentials (включая Microsoft) хранятся только server-side в application-layer AES-GCM envelope, привязанном к canonical user/identity/provider/subject. Provider token не является Never access/refresh token, не возвращается в login/link/refresh API и не должен попадать в логи или клиентское secure storage. Ротация `NEVERLAUNCHER_AUTH_TOKEN_SECRET` требует контролируемой миграции/повторной авторизации provider credentials.

## Passkeys / WebAuthn и step-up

С `0.11.7` phishing-resistant authentication реализована WebAuthn passkeys. В production RP ID и origins задаются явно; origin должен быть HTTPS и находиться внутри RP ID. Registration и assertion требуют user verification, проверяют challenge/origin/RP ID hash и криптографическую подпись; challenge single-use и хранится в PostgreSQL. Значения private key authenticator никогда не передаются Backend — сохраняется только COSE public key и credential metadata.

Критические действия не полагаются только на факт существования активной session: Backend проверяет `auth_strength` и свежий `auth_time`. Для операций, требующих phishing-resistant step-up, TOTP недостаточен.

## Session Management 2.0

С `0.11.8` access tokens являются подписанными JWS/JWT с обязательными `iss`, `aud`, `sub`, `sid`, `jti`, `iat`, `exp`, `kid`, `auth_time` и `amr`. Для rotation используйте `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` и переключайте `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID`, сохраняя предыдущий verification key до истечения всех выпущенных им access tokens. `AUTH_TOKEN_SECRET` остаётся обязательным root secret и backward-compatible single-key fallback.

Session risk хранится в PostgreSQL: изменение IP/User-Agent переводит session в `elevated`, refresh-token replay — в `compromised` с отзывом всей token family. Массовый provider revoke доступен только после свежего phishing-resistant step-up. Provider logout и Never session logout являются разными действиями: отзыв внешнего provider credential сам по себе не завершает Never session.

## Minecraft Auth Compatibility 2.0

С `0.11.9` Never access token и Minecraft access token — разные credentials. Minecraft token является opaque `nlmc_*`, в persistent store сохраняется только его SHA-256 hash; запись привязана к canonical user, Minecraft profile и parent Never session. `validate`, `join` и `hasJoined` повторно проверяют активность parent session, поэтому Never logout/revoke не оставляет отдельную игровую сессию действительной. Yggdrasil refresh потребляет старый Minecraft token и не допускает его повторного использования.

Minecraft UUID не зависит от email, username внешнего provider или Microsoft/OIDC claims. Authlib-injector никогда не подхватывается из произвольного локального пути: NeverRuntime ищет его только среди файлов подписанного release manifest и передаёт Backend URL только через HTTPS (HTTP разрешён лишь для localhost development). Minecraft access token редактируется в launch preview/log metadata.

Этот слой не подменяет Microsoft/Mojang entitlement: успешный Microsoft identity login не доказывает владение официальной копией Minecraft.

## Обязательные production-настройки

Для production-окружения используйте persistent backend и сильные секреты:

```env
NEVERLAUNCHER_ENV=production
NEVERLAUNCHER_REPOSITORY_DRIVER=postgres
NEVERLAUNCHER_SQL_DRIVER=pgx
NEVERLAUNCHER_DATABASE_DSN=postgres://neverlauncher:password@postgres:5432/neverlauncher?sslmode=disable
NEVERLAUNCHER_AUTH_TOKEN_SECRET=replace-with-at-least-32-random-bytes
NEVERLAUNCHER_AUTH_TOKEN_AUDIENCE=neverlauncher-api
NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID=primary
# NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON={"primary":"...","previous":"..."}
NEVERLAUNCHER_PERSISTENT_SESSIONS=true
NEVERLAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION=true
NEVERLAUNCHER_BACKUP_ROOT=/var/lib/neverlauncher/backups
NEVERLAUNCHER_WEBAUTHN_RP_ID=example.com
NEVERLAUNCHER_WEBAUTHN_RP_NAME=NeverLauncher
NEVERLAUNCHER_WEBAUTHN_ORIGINS=https://admin.example.com
NEVERLAUNCHER_CORS_ALLOWED_ORIGINS=https://admin.example.com
```

В production Backend API fail-closed отклоняет memory repository, слабый token secret, HTTP public URL, wildcard/пустой CORS allowlist, пересечение backup/storage каталогов и неполную S3-конфигурацию. Runtime-переменной с резервным паролем администратора нет: вход проверяет только сохранённый password hash. Первый администратор создаётся отдельным bootstrap-flow с одноразовым `NEVERLAUNCHER_BOOTSTRAP_TOKEN`.

## Backup и восстановление

Production backup хранится отдельно от рабочего storage в `NEVERLAUNCHER_BACKUP_ROOT`. Архив содержит PostgreSQL custom dump, реальные storage-объекты и manifest с SHA-256. Перед восстановлением используйте `nl backup restore-dry-run`; реальный `nl backup restore` требует точного `--confirm <backupId>` и явного выбора `--database true` и/или `--storage true`.

S3 работает fail-closed: Backend не имеет автоматического fallback на local storage при ошибке подключения или health-check.

Backup/restore выполняются внутри maintenance-lock: mutating API-запросы блокируются на время согласованного снимка или восстановления. Перед destructive restore автоматически создаётся safety backup. Для local storage восстановление подготавливается в соседнем каталоге и переключается атомарным `rename`; PostgreSQL `pg_restore` выполняется с `--single-transaction`.

## Подпись production-релиза

`SHA256SUMS.sig` — реальная Ed25519-подпись байтов `SHA256SUMS`, а не повторный checksum. Private key передаётся только через `--private-key` или `NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE`; он не включается в release bundle. Проверка требует отдельный доверенный public key через `--public-key` или `NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE`. Public key из самого bundle не принимается как trust anchor.

Source archive формируется из git-tracked файлов либо строгого allowlist при отсутствии `.git`, исключает symlink/secret paths и до формирования release manifest проходит secret scan. `release verify` fail-closed проверяет наличие, размер и SHA-256 каждого `required=true` artifact, затем SHA256SUMS, Ed25519 signature и detached подпись `PROVENANCE.json.sig`. Provenance имеет формат in-toto Statement / SLSA v1, а SBOM — SPDX 2.3 и строится из dependency manifests/locks.

### Compatibility certification в release trust boundary

Команда `release publish-check` дополнительно требует `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json` и `COMPATIBILITY_CERTIFICATION.json`. Certification не доверяет полю `status: passed` само по себе: повторно проверяются exact release version/commit/run ID, target identity, concrete loader version, обязательные actual-client checks и per-target `evidenceSha256`. SHA-256 matrix/targets фиксируются в certification, а все три файла входят в подписанный `SHA256SUMS`; подмена compatibility evidence после сборки поэтому делает release signature/checksums недействительными.


## Жизненный цикл signing-ключей

`nl security rotate-key` создаёт новую Ed25519 пару через CSPRNG и сохраняет metadata в persistent `trusted-keys.json`; private key записывается с правами `0600`. Предыдущий активный ключ переводится в verify-only либо сразу отзывается по явному флагу. `nl security revocation-list --revoke <keyId>` фиксирует отзыв в registry, а verify-flow с `--registry-dir` отклоняет подпись от отозванного public key. `nl security attest` создаёт detached Ed25519 signature для указанного artifact.

Published package после перехода в `published` считается неизменяемым: загрузка файлов, изменение manifest/status и повторная публикация запрещены на HTTP и repository уровнях. Любое изменение содержимого выпускается новой версией.


## Compatibility materialization hardening

Операции Vanilla/Fabric/Quilt/Forge/NeoForge materialization сериализуются exclusive lock-файлом внутри конкретного `clientDir`. Это предотвращает одновременную запись одного `version.json`, Maven artifact, asset или processor output несколькими CLI-процессами. Запись в client tree выполняется только через lexical path validation и `Lstat` существующих компонентов; symlink-компоненты отклоняются. Symlink artifact также запрещён при построении client package.

Transient upstream HTTP ошибки `408/425/429/500/502/503/504` и временные transport errors повторяются ограниченное число раз; `Retry-After` ограничен верхним пределом, поэтому внешняя сторона не может удерживать materializer в бесконечном ожидании. Размер одиночного compatibility artifact ограничен, временные `.nlpart` файлы не становятся рабочим artifact до hash/size verification и portable replacement.

Generated native directories не считаются кэшем: `natives/<os>` пересоздаётся перед extraction, что исключает stale DLL/SO/dylib из предыдущей materialization. Forge/NeoForge installer scratch `data/` аналогично очищается перед processor execution.

## Managed Java и Vanilla supply chain

NeverRuntime устанавливает Managed Java только из HTTPS metadata Adoptium/Temurin. Перед публикацией runtime в локальный cache проверяются ожидаемый размер и SHA-256 архива, platform metadata и фактическая major-версия через `java -version`. Загрузка выполняется во временный файл, распаковка — в staging; path traversal и внешние symlink после извлечения отклоняются, а рабочий каталог появляется только после атомарного rename. Повреждённый ранее установленный runtime помещается в quarantine и не используется для запуска.

Vanilla materializer получает Mojang `version_manifest_v2.json`, затем проверяет опубликованный Mojang SHA-1 для `version.json`, client/libraries/assets/native/logging artifacts и ожидаемый размер. SHA-1 здесь является upstream-идентификатором Mojang, а не внутренним trust primitive NeverLauncher: после материализации каждый файл получает SHA-256 и далее проходит стандартный signed immutable release lifecycle NeverLauncher. HTTP разрешён только для loopback fixture-тестов; внешние источники должны использовать HTTPS. Native ZIP распаковываются с проверкой traversal, symlink и escape за пределы целевого каталога.

Fabric/Quilt materializer использует официальный Meta API только как online source до публикации release. Mutable `latest` никогда не сохраняется в published release: сначала выбирается конкретная loader version. Полученный loader profile проверяется относительно выбранной Minecraft-версии и выбранного loader artifact, затем нормализуется; Maven JAR скачиваются только по HTTPS и в strict mode обязаны иметь корректный repository `.sha1`. В profile записываются точные URL, SHA-1 и фактический размер; сам profile и JAR затем фиксируются SHA-256 и защищаются обычной Ed25519-подписью immutable Never manifest. Компрометация локального profile после публикации обнаруживается Compatibility Engine trust boundary.

Forge/NeoForge materializer принимает только processor-based installer format, загружает `installer.jar` по HTTPS и в strict mode требует корректный Maven SHA-1. `install_profile.json` и `version.json` читаются непосредственно из уже проверенного installer JAR. Встроенные `maven/` и `data/` entries извлекаются с защитой от path traversal и symlink. Processor запускается как прямой Java process без shell interpolation; `Main-Class` берётся из manifest processor JAR, classpath строится только из materialized Maven artifacts, а timeout ограничивает зависший процесс. Installer variables и Maven references нормализуются в локальные пути. Заявленные processor outputs проверяются по SHA-1/SHA-256 после выполнения и перед повторным использованием. Installer JAR, временные data и служебное состояние остаются под `.neverlauncher/` и исключаются из опубликованного client package; в immutable release попадают только нормализованные runtime artifacts и child version profile. Legacy Forge pre-1.13 не считается поддерживаемым security boundary этой версии.

## Доказательство реального Minecraft Client E2E

Release gate не принимает synthetic Java fixture или один Minecraft handshake как доказательство совместимости клиента. CI материализует полный Vanilla 1.21.1 из Mojang metadata, выполняет локальный SHA-256 package verify, загружает package через Backend API, публикует Ed25519-signed immutable manifest, затем скачивает release заново в чистый каталог через NeverRuntime. Запуск выполняется реальным Minecraft Java Client под изолированным Xvfb display. Успех подтверждается одновременно ServerBridge allow-событием и серверным `E2EPlayer joined the game`.

`e2e/scripts/publish-client-package.py` повторно вычисляет SHA-256 и размер каждого локального artifact непосредственно перед upload и сверяет их с package manifest и ответом Backend API. Это предотвращает ситуацию, когда E2E публикует дерево, изменившееся после materialization. Runtime watchdog `--max-runtime-seconds` используется только как ограничитель длительно работающего процесса: после таймаута NeverRuntime сам завершает дочернюю JVM и фиксирует `timedOut`; обычный production launch без флага остаётся неограниченным.

## Hardening публичной Compatibility Matrix

Не хранит статусы совместимости в исходном `compatibility/targets.json`. Этот файл задаёт только ожидаемые Minecraft/loader/OS/arch targets. Каждый PASS создаётся `run-compatibility-case.sh` из фактического production E2E и содержит exact `GITHUB_SHA`/`GITHUB_RUN_ID`. Агрегатор отклоняет missing/duplicate targets, несовпадение commit/run, mutable loader version после resolution и отсутствие package verify, Ed25519 signature, clean sync, actual-client launch, Paper world join или revoke/deny evidence.

Compatibility uploader запрещает symlink path и повторно разрешает каждый package path внутри client root непосредственно перед чтением. Generic E2E связывает ServerBridge profile с проверяемым loader target; hard-coded Vanilla profile для Fabric/Quilt/Forge/NeoForge запрещён. Матрица публикуется как GitHub Actions Summary и JSON/Markdown artifact, а repository policy запрещает возвращение ручных PASS markers или fixture-based compatibility evidence.

## CORS

`NEVERLAUNCHER_CORS_ALLOWED_ORIGINS` содержит явный список HTTPS origin через запятую. `*` в production запрещён. Специальный `e2e-production` разрешает HTTP только для loopback `localhost/127.0.0.1/::1` и предназначен исключительно для автоматизированного production E2E.

## Сообщение об уязвимостях

Если вы нашли уязвимость, не публикуйте её в открытых задачах до первичного разбора.

Рекомендуемый порядок:

1. Подготовьте описание проблемы.
2. Укажите затронутые компоненты: Backend API, CLI, Desktop Launcher, Admin Panel, ServerBridge, манифесты, storage или deployment.
3. Приложите минимальные шаги воспроизведения.
4. Укажите возможное влияние на пользователей или серверные проекты.
5. Передайте отчёт владельцу проекта через приватный security-канал, указанный в репозитории проекта.

## Критичная область безопасности

Критичными считаются проблемы, затрагивающие:

- обход авторизации или RBAC;
- подмену package/runtime/project manifests;
- подмену файлов клиента;
- обход SHA-256/integrity verification;
- небезопасный запуск Java/Minecraft;
- утечку refresh/session/server tokens;
- обход ServerBridge validate-join;
- выполнение произвольного кода;
- path traversal при работе с архивами и storage;
- доступ к чужим проектам, пакетам, audit events или backup artifacts.

## ServerBridge security

ServerBridge должен работать в deny-by-default режиме:

- сервер регистрируется через отдельный bridge token;
- validate-join вызывается на Backend API;
- heartbeat/audit-event пишутся на backend;
- недоступность backend трактуется как deny или degraded mode только при явном разрешении оператора;
- ротация server token должна быть штатной операцией.

## Compatibility Engine trust boundary

При `classpathStrategy=compatibility` `version.json`, родительские metadata из `inheritsFrom` и каждый JAR, попавший в resolved classpath, должны присутствовать в подписанном release manifest. NeverRuntime не доверяет локальному metadata-файлу только потому, что он находится в каталоге клиента. Backend также запрещает публикацию compatibility release без обязательного `versionMetadataPath` (по умолчанию `versions/<version>/<version>.json`) и отклоняет traversal/небезопасные пути.

Mojang rules обрабатываются до выбора library/native artifacts. Файлы с `targetOs` другой платформы не участвуют в verify/sync текущей ОС; `targetOs` и `executable` являются частью подписанного manifest metadata.

## Целостность пакетов

Для клиентских пакетов обязательны:

- file-level SHA-256 manifest;
- проверка целостности перед запуском;
- repair mode вместо слепого перезаписывания;
- release artifact checksums;
- запрет доверять локальному состоянию Desktop Launcher без server-side session.

## Псевдонимы совместимости

Backend API может читать устаревшие compatibility aliases только для миграции, но документация и production-развёртывание используют канонические переменные:

- `NEVERLAUNCHER_DATABASE_DSN` вместо `NEVERLAUNCHER_DATABASE_URL`;
- `NEVERLAUNCHER_AUTH_TOKEN_SECRET` вместо `NEVERLAUNCHER_TOKEN_SECRET` или `NEVERLAUNCHER_JWT_SECRET`;
- `NEVERLAUNCHER_STORAGE_LOCAL_PATH` вместо `NEVERLAUNCHER_STORAGE_LOCAL_ROOT`;
- `NEVERLAUNCHER_REDIS_ADDR` вместо `NEVERLAUNCHER_REDIS_URL`.
