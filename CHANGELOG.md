# Changelog

## 0.13.5 — Minecraft/ServerBridge integrity enforcement

`0.13.5` переносит Guard Attestation из одноразового момента выдачи Minecraft token в live gameplay boundary. Integrity snapshot сохраняется вместе с Minecraft session, а каждый последующий token validation, Yggdrasil join/hasJoined и ServerBridge validate-join/has-joined повторно проверяет текущий Guard release allowlist. Удаление release hash из production policy немедленно отзывает уже выданные игровые credentials и связанные ServerBridge joins.

### Minecraft integrity persistence and live revocation

- Migration `0019_minecraft_serverbridge_integrity_0135.sql` сохраняет verified Guard attestation/evidence/release SHA-256, launcher version и verification time в `minecraft_sessions`; API и CLI используют идентичную sealed migration.
- `/api/v1/session/join` для Windows Guard-enforced device теперь обязан получить конкретный `minecraftAccessToken` и сохранить `minecraftSessionId`. Это закрывает прежний обход, при котором Never-session могла создать ServerBridge join без связи с Guard-verified Minecraft credential.
- Minecraft token validation, Yggdrasil join/hasJoined и ServerBridge validation заново сверяют snapshot с `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`. Release revocation действует на уже активные sessions без ожидания их TTL.
- Desktop передаёт только что выданный Minecraft access token в ServerBridge join до запуска Java, поэтому gameplay join связан с тем же device/session/binding epoch и Guard evidence, которые прошли Backend verification.

### ServerBridge artifact enforcement

- Velocity/Paper/Purpur вычисляют SHA-256 собственного запущенного JAR через `CodeSource` и отправляют его в heartbeat и каждый `validate-join`. При невозможности измерить JAR плагин fail-closed, когда `security.requireIntegrity=true` (production default).
- Backend принимает heartbeat только если `pluginVersion + serverType + pluginSha256` присутствуют в `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`. Accepted measurement сохраняется в ServerBridge state и повторно проверяется по текущему allowlist на каждом gameplay validation.
- `validate-join` обязан повторить тот же version/hash, что был подтверждён heartbeat. Ротация server token сбрасывает integrity measurement и требует нового heartbeat. Legacy/authlib `has-joined` также требует актуальный verified bridge measurement.
- `scripts/build/bridge-plugins.sh` строит реальные platform JAR, вычисляет их SHA-256, записывает hashes в `PLUGIN_MANIFEST.json` и генерирует `BRIDGE_RELEASE_ALLOWLIST.json`; release bundle включает оба файла. Production startup требует `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`.

ServerBridge JAR hash — application-level self-measurement, а не hardware/server attestation самого Minecraft-сервера: полностью скомпрометированный host с server token может подделывать пользовательский процесс. Enforcement предназначен для release allowlisting, accidental/unauthorized artifact drift и live backend policy, а не для утверждения kernel-level integrity удалённого сервера.

## 0.13.4 — Guard Attestation + Backend verification

`0.13.4` связывает локальный NeverGuard Windows boundary с Backend: сервер выдаёт persistent single-use challenge, отдельный `neverguard.exe` формирует свежую challenge-bound attestation поверх Integrity Evidence v1 и enforced process policy, а hardware P-256 device key подписывает каноническую привязку `user + device + session + bindingEpoch + release + attestation`. Backend пересчитывает evidence/attestation digests, проверяет device signature, freshness/replay и точные SHA-256 release binaries; только после этого выдаётся одноразовый короткоживущий Guard launch ticket, обязательный для Minecraft session в production.

### Guard-side attestation

- Authenticated IPC поднят до v3: request MAC теперь включает payload, а команда `guard-attestation` принимает server challenge только внутри уже аутентифицированной Desktop↔NeverGuard session. Guard заново собирает Integrity Evidence, прикладывает текущий enforced process-policy report и HMAC-привязывает attestation digest к IPC session.
- Canonical attestation фиксирует challenge hash/ID, evidence ID/digest, SHA-256 Guard/Desktop, module-set fingerprints, Authenticode results, process-policy flags и collection time. Desktop повторно проверяет challenge, evidence, policy, digest и session proof до использования результата.
- Windows integration test выполняет реальный handshake с `neverguard.exe`, получает challenge-bound attestation и проверяет связь с PID/process boundary.

### Backend verification and launch gate

- Добавлены `POST /api/v1/auth/devices/{deviceId}/guard-attest/begin|complete`. Challenge хранится в Repository, привязан к текущим `user/device/session/bindingEpoch/launcherVersion/keyFingerprint`, имеет TTL 90 секунд и потребляется атомарно.
- Complete требует hardware-bound P-256 trusted device с актуальной device attestation. Backend заново вычисляет Integrity Evidence SHA-256 и Guard Attestation SHA-256, проверяет freshness, parent boundary, enforced process policy, device signature и release allowlist.
- Успешная проверка выпускает persistent single-use Guard launch ticket с TTL 90 секунд. `/api/v1/minecraft/session` в production требует этот ticket и потребляет его атомарно; replay получает `412 Precondition Failed`.
- `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` обязателен в production. Windows release script формирует `GUARD_RELEASE_ALLOWLIST.json` из фактических SHA-256 `neverguard.exe` и Desktop executable; policy может дополнительно требовать trusted Authenticode.
- Это application-level server verification, а не TPM/Measured Boot quote и не kernel anti-cheat. Backend доверяет зарегистрированному hardware device key, challenge freshness, точным release hashes и evidence/policy, сформированным allowlisted NeverGuard/Desktop.

## 0.13.3 — Windows runtime/process policy enforcement

`0.13.3` переводит NeverGuard Windows policy из наблюдаемого evidence в реально применяемую runtime boundary. Политики включаются fail-closed: `neverguard.exe` усиливает собственный процесс до инициализации Tokio, а Java/Minecraft создаётся suspended и начинает выполнение только после успешного назначения в проверенный Windows Job Object.

### NeverGuard self-policy

- До создания async runtime NeverGuard применяет `SetProcessMitigationPolicy` для Dynamic Code, Extension Point Disable, Strict Handle Check, Image Load и Child Process policy, затем повторно считывает каждую policy через `GetProcessMitigationPolicy`. Ошибка применения или верификации завершает guard до открытия authenticated session.
- Guard запрещает dynamic code и создание дочерних процессов, отключает legacy extension points, включает strict-handle checks и блокирует remote/low-integrity image loading с предпочтением System32. Применённое состояние доступно через authenticated IPC `process-policy` и привязано к `ready` handshake.
- IPC protocol поднят до v2: ready proof теперь включает process-policy version/enforced bit, поэтому клиент не может принять старый guard как policy-enforced instance.

### Minecraft runtime tree enforcement

- NeverRuntime на Windows создаёт Java с `CREATE_SUSPENDED`. До выполнения пользовательского bytecode процесс назначается в новый Job Object с `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` и `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`. Breakaway flags запрещены и фактическая membership/limit mask проверяется Win32 API.
- Только после успешного `AssignProcessToJobObject` + `IsProcessInJob` + `QueryInformationJobObject` NeverRuntime находит suspended primary thread и вызывает `ResumeThread`. Любая ошибка до resume блокирует launch и инициирует termination child process.
- Job handle живёт столько же, сколько supervised runtime. Закрытие launcher/supervisor boundary завершает runtime tree через kill-on-close; `ProcessStatus` публикует фактически применённый `windowsProcessPolicy`.
- Запрет dynamic code намеренно не применяется к Java/Minecraft process: HotSpot JIT требует executable generated code. Вместо несовместимого флага runtime ограничивается Job Object/process-tree policy, а строгие mitigations применяются к самому небольшому NeverGuard process.

### Release verification

- Windows native test проверяет реальное создание suspended child, Job Object assignment, non-breakaway policy и resume; NeverGuard integration test проверяет authenticated process-policy report вместе с Integrity Evidence v1.
- CI/preflight получили обязательный `neverguard-process-policy-0133.py`; Windows job запускает policy unit/native tests, process-boundary integration test и `clippy -D warnings`.
- Это user-mode Windows process policy enforcement, а не kernel anti-cheat и не server-verifiable attestation. Оно не использует aggressive hooks и служит enforced runtime boundary для последующих NeverGuard integrity/attestation этапов.

## 0.13.2 — Windows Integrity Evidence v1

`0.13.2` добавляет первый рабочий Windows integrity-evidence слой поверх отдельного NeverGuard process boundary из `0.13.1`. Evidence собирается внутри `neverguard.exe` только после mutual-authenticated IPC и перед каждым Windows Minecraft launch; ошибка сбора, нарушение parent boundary, повреждённый digest или session proof блокируют launch.

### Evidence collection

- NeverGuard независимо сверяет фактический parent PID через Windows Toolhelp snapshot с PID, переданным Desktop, и завершает startup при mismatch. Это усиливает прежнюю проверку PID внутри handshake фактическим OS-observed parent relation.
- Для `neverguard.exe` и процесса launcher собираются image path, SHA-256 файла, размер/mtime и Windows process creation FILETIME. Хэш считается самим guard с диска, а не принимается от Desktop.
- Authenticode проверяется локальным `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` без UI и без сетевой загрузки revocation-данных; evidence сохраняет `trusted` и исходный WinTrust status code, поэтому unsigned/невалидный binary не маскируется как trusted.
- `GetProcessMitigationPolicy` снимает raw flags DEP, ASLR, Dynamic Code, Extension Point Disable, CFG, Binary Signature, Image Load, Child Process, User Shadow Stack и SEHOP. Неподдерживаемая отдельная policy попадает в `queryFailures`, сохраняя остальные evidence.
- Toolhelp module snapshot для guard и launcher превращается в детерминированный SHA-256 fingerprint набора загруженных module paths + SHA-256 содержимого каждого module file + file metadata; отдельно публикуются только basename нестандартных non-system modules, чтобы не раскрывать дополнительные пользовательские пути.

### Authenticated evidence transport

- Новый IPC command `integrity-evidence` доступен только внутри уже authenticated NeverGuard session. Сбор файлов/Win32 evidence выполняется через blocking worker, не блокируя Tokio IPC runtime.
- Canonical evidence core получает собственный SHA-256 (`evidenceSha256`). Guard дополнительно HMAC-привязывает digest к текущему IPC session key (`sessionProof`); Desktop заново проверяет schema/version, PID boundary, digest и proof constant-time перед возвратом evidence вызывающему коду.
- Desktop export-команда `neverguard_integrity_evidence` возвращает только уже локально проверенный payload. Windows `launch_minecraft` становится fail-closed на evidence collection/verification.

### Verification and security boundary

- Windows integration test запускает настоящий `neverguard.exe`, проходит handshake, получает Integrity Evidence v1, проверяет PID/hash/module/session-proof shape и затем корректный shutdown. Отдельные platform-independent unit tests защищают canonical evidence digest от незаметной модификации полей.
- CI/preflight получили обязательный gate `neverguard-integrity-evidence-0132.py`; Windows job компилирует и тестирует integrity implementation вместе с process-boundary integration test и clippy.
- Integrity Evidence v1 является **local Windows evidence**. `0.13.2` не объявляет его server-verifiable attestation, kernel anti-cheat, memory integrity proof или TPM-backed quote; cryptographic server verification остаётся отдельным следующим этапом NeverGuard.

## 0.13.1 — NeverGuard Windows: process boundary + authenticated IPC

`0.13.1` вводит первый production runtime boundary NeverGuard для Windows. Guard запускается отдельным `neverguard.exe` рядом с Desktop, а Windows launch становится fail-closed: Minecraft не стартует, пока Desktop не поднимет guard и не подтвердит authenticated IPC.

### Process boundary

- `neverguard.exe` является отдельным Rust process с собственным entrypoint; Desktop не загружает guard-код как hook/DLL в Minecraft-процесс.
- Desktop генерирует криптографически случайный 256-bit bootstrap secret и передаёт его guard только через унаследованный stdin. Secret не помещается в argv, environment, config или временный файл и zeroize-ится после handshake.
- IPC использует Windows Named Pipe в случайном per-launch namespace `NeverLauncher.Guard.*`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, один server instance и `PIPE_REJECT_REMOTE_CLIENTS`.
- Guard принимает только клиент с ожидаемым parent PID; знание PID не является аутентификацией и проверяется только вместе с possession bootstrap secret.

### Authenticated IPC v1

- Handshake взаимный: client/server nonces, HMAC-SHA-256 proofs в разных directions и отдельный derived session key. Transcript привязан к endpoint, обоим PID, guard start time и обоим nonce.
- После handshake каждый request/response имеет HMAC и sequence/request ID; guard отклоняет replay и out-of-order requests, malformed frame, protocol mismatch и MAC mismatch. Размер JSON frame ограничен 64 KiB.
- Реальные команды `ping`, `status`, `shutdown` проходят только после authentication. Потеря pipe завершает guard session; Desktop держит child handle с kill-on-drop.
- Windows integration test запускает настоящий `neverguard.exe`, проходит handshake/ping/status/shutdown и проверяет привязку к parent PID.

### Distribution and release gate

- `scripts/release/build-windows-desktop.ps1` собирает Desktop и NeverGuard release binaries, кладёт `neverguard.exe` рядом с Desktop, фиксирует SHA-256/size в `WINDOWS_PACKAGE_MANIFEST.json` и формирует Windows ZIP.
- Основной CI получил обязательный `windows-2022` job с real process integration test, clippy и сборкой side-by-side package; Linux release-candidate job зависит от успешного NeverGuard Windows job.
- Добавлен gate `neverguard-windows-0131.py`; он проверяет, что process/IPC/security/release wiring не заменены декларацией.

## 0.13.0 — Device Trust Release

`0.13.0` закрепляет Device Trust как release-level production boundary. Схема остаётся на sealed migration `0018_device_trust_stabilization_01210`: пустая migration ради номера версии не добавляется. Backend публикует machine-readable release contract через auth capabilities, а PostgreSQL E2E требует этот contract и `/ready` с актуальной migration перед lifecycle-проверками.

### Release certification

- Public Device Trust matrix теперь требует `deviceTrustRelease0130` на PostgreSQL protocol target и native Linux/Windows/macOS targets.
- Native evidence дополнительно запускает fail-closed key lifecycle test; protocol evidence проверяет runtime release contract, schema readiness и сохраняет их hash-verified evidence.
- CLI release pipeline получил `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json`. Certification привязана к exact product version, source commit, Actions run ID и SHA-256 embedded targets/matrix.
- Начиная с `0.13.0`, `nl release publish-check` требует одновременно Minecraft Compatibility certification и Device Trust certification. Изменённая, неполная или относящаяся к другому commit trust matrix блокирует публикацию.
- `scripts/release/build-release.sh` принимает `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE` / `NEVERLAUNCHER_DEVICE_TRUST_TARGETS_FILE`; CI bundle без публичного evidence остаётся release candidate и не считается официально publishable.

### Runtime boundary

- `/api/v1/auth/capabilities` и Desktop auth policy публикуют Device Trust Release contract: session↔device binding, device-bound refresh, risk enforcement, Minecraft/ServerBridge enforcement, permanent revoke/tombstones, dual-proof rotation и phishing-resistant recovery.
- Hardware boundary не переименована в vendor attestation: P-256 challenge-response по-прежнему означает proof-of-possession, а `vendorProvenance=not-remotely-verified`.
- Gate `device-trust-release-0130.py` запрещает пустую `0019`, проверяет migration parity, release certification code, runtime contract, public targets и обязательную CI/preflight интеграцию.

## 0.12.10 — Migration + stabilization

`0.12.10` стабилизирует накопленный Device Trust schema/runtime после `0.12.4–0.12.9` и делает upgrade с реальной `0.12.9` БД отдельным обязательным release invariant. Главная исправленная production-проблема: constraint `device_challenges_purpose_check`, созданный в `0.12.4`, не был расширен после появления `key-rotate`/`key-recover` в `0.12.8`, из-за чего PostgreSQL мог отклонять replacement challenge, хотя memory regression проходил.

### Schema stabilization

- Migration `0018_device_trust_stabilization_01210.sql` синхронно входит в API/CLI catalogs и расширяет challenge purpose до `register`, `session-bind`, `attest`, `key-rotate`, `key-recover`.
- Старые empty-string sentinels в `trusted_devices.replaced_by_device_id` и `minecraft_sessions.trusted_device_id` переводятся в SQL `NULL`; repository scanners/writers используют nullable SQL semantics.
- Валидные legacy revoked-device строки нормализуются в единое terminal state (`trust_state=revoked`, `attestation_state=revoked`, timestamp/reason); просроченные незавершённые challenge помечаются consumed.
- Перед установкой ограничений migration fail-closed проверяет cross-user replacement links, session/device ownership, binding shape и Minecraft session/profile/device ownership. Повреждённая или неоднозначная БД не «чинится» молча.
- После проверки устанавливаются ownership foreign keys и lifecycle/shape CHECK constraints для trusted devices, auth sessions и Minecraft trust snapshots. Replacement chain остаётся permanent tombstone и не может ссылаться на устройство другого пользователя.

### Upgrade E2E и release enforcement

- `e2e/scripts/run-device-trust-migration-e2e.sh` создаёт точную schema `0.12.9` (sealed migrations `0001..0017`), сеет допустимые legacy states, доказывает pre-upgrade failure `key-rotate`, затем запускает shipping CLI `nl db migrate apply/verify` и проверяет `0018` postconditions.
- Upgrade E2E требует, чтобы cross-user auth binding, replacement link и Minecraft device snapshot после migration отклонялись самой PostgreSQL БД.
- Production Device Trust E2E публикует upgrade evidence вместе с runtime evidence; public trust matrix требует `migrationStabilization01210`, поэтому PASS без проверенного `0.12.9 → 0.12.10` upgrade невозможен.
- Gate `device-trust-migration-stabilization-01210.py` включён в repository policy, CI и release preflight; strict Device Trust flow запускает migration E2E перед lifecycle E2E.


## 0.12.9 — Device Trust E2E + public trust matrix

`0.12.9` переводит Device Trust из набора отдельных regression/release gates в публично проверяемый end-to-end контур. Новый production E2E поднимает Backend с реальным PostgreSQL/Redis, применяет sealed migrations и проходит полный lifecycle device identity реальными Ed25519/P-256 подписями. PASS не хранится в репозитории: public trust matrix принимает только machine-verifiable evidence от exact Git commit и GitHub Actions run ID.

### Production Device Trust E2E

- `e2e/scripts/run-device-trust-e2e.sh` проверяет registration + single-use challenge replay deny, server-authoritative `binding_epoch`, device-bound refresh proof, ServerBridge trust before/after replacement, dual-proof key rotation, permanent old-key tombstone, persisted risk step-up, P-256 challenge-response attestation/replay deny, recovery deny без phishing-resistant step-up, успешный recovery после реальной WebAuthn P-256 registration/assertion ceremony и permanent revoke cascade.
- E2E использует production PostgreSQL repository с explicit `nl db migrate apply`/`verify`; runtime проверяет replacement chain непосредственно в PostgreSQL. Ed25519/P-256 device signatures и WebAuthn ES256 assertion создаются test-only OpenSSL helpers; private keys остаются только во временном runtime directory.
- Public evidence намеренно не содержит access/refresh tokens или private-key material; script fail-closed сканирует evidence перед публикацией. P-256 case подтверждает protocol proof-of-possession и явно фиксирует `vendorHardwareProvenance=not-verified`.

### Public Device Trust Matrix

- `device-trust/targets.json` задаёт четыре обязательных target без editable PASS/FAIL: PostgreSQL protocol E2E на Linux x86_64 и native Tauri/key-policy tests на Linux, Windows и macOS.
- `.github/workflows/device-trust.yml` генерирует dynamic matrix, собирает per-target `device-trust-result.json` и агрегирует `matrix.json`/`matrix.md` только при совпадении version, target, commit, run ID и checks; каждый evidence-файл обязан существовать и совпасть с зафиксированным SHA-256.
- Native targets компилируют Tauri key lifecycle и запускают security-policy unit tests, включая generation-scoped hardware labels, replacement payload, refresh binding и attestation payload. Матрица прямо указывает, что headless CI не является доказательством фактической работы OS secure storage/TPM/Secure Enclave на конкретном пользовательском устройстве.
- Gate `device-trust-e2e-matrix-0129.py` включён в repository policy, основной CI и preflight; strict preflight дополнительно запускает PostgreSQL Device Trust E2E.

## 0.12.8 — Cross-platform hardening + key recovery/rotation

`0.12.8` завершает lifecycle Device Trust для потери и плановой замены локального device key. Rotation сохраняет continuity только при одновременном proof-of-possession старым и staged-новым ключом. Recovery не требует утраченного private key, но требует свежий phishing-resistant account step-up и proof новым staged key. В обоих случаях Backend создаёт новую device identity, перепривязывает текущую session с новым `binding_epoch`, превращает старый fingerprint в permanent tombstone и отзывает credentials, связанные со старой identity.

### Runtime key lifecycle

- Desktop/Tauri использует двухфазный `stage → server ceremony → commit`: рабочий локальный ключ не заменяется до успешного server response; при ошибке до commit staged key удаляется, а после server commit staged metadata сохраняется для reconciliation.
- Hardware P-256 replacement больше не использует детерминированный label `backend+user`: каждый staged generation получает отдельный label, поэтому TPM/Secure Enclave key действительно меняется. Software Ed25519 replacement хранится отдельной staged записью OS keyring.
- Rotation подписывает один canonical `NeverLauncher Device Key Replacement v1` payload старым и новым ключом. Recovery требует свежий `phishing-resistant` step-up и подписывает тот же server-issued одноразовый challenge новым ключом.
- PostgreSQL replacement выполняется транзакционно: создаётся новый trusted device, текущая auth session получает новый device и `binding_epoch`, старая identity становится tombstone с replacement link, sibling sessions/refresh families/Minecraft sessions и незавершённые challenges отзываются. ServerBridge joins инвалидируются после commit.
- Ordinary registration из уже bound session запрещена: replacement нельзя обойти вторым ключом в той же доверенной session. Если server record исчез/отозван, Desktop больше не удаляет локальный ключ автоматически и переводит пользователя в recovery.
- Migration `0017_device_key_recovery_rotation_0128.sql` хранит replacement chain (`replaced_at`, `replaced_by_device_id`, `replacement_reason`) одинаково в API и CLI catalogs.

### Verification / release gates

- HTTP regressions проверяют обязательность old+new proof для rotation, fresh phishing-resistant step-up для recovery, permanent tombstone и запрет bypass через обычную регистрацию. Предыдущий Minecraft re-bind regression переведён на настоящий key-rotation flow.
- Gate `cross-platform-key-recovery-0128.py` подключён к preflight, repository policy и CI и проверяет backend transaction, migration parity, native staged-key lifecycle, Desktop reconciliation и реальные Go regressions.

## 0.12.7 — Minecraft / ServerBridge trust enforcement

`0.12.7` переносит Device Trust из launcher/auth boundary непосредственно в Minecraft gameplay boundary. Minecraft session и ServerBridge join теперь фиксируют server-authoritative snapshot `trusted_device_id + binding_epoch`, а последующая server-side проверка повторно сверяет его с текущей Never session, состоянием trusted device и risk decision. Поэтому старый Minecraft token или join нельзя продолжить использовать после re-bind, revoke или permanent risk transition.

### Runtime enforcement

- `POST /api/v1/minecraft/session` выдаёт официальный Minecraft credential только active Never session с verified bound device и допустимой risk policy. Persisted Minecraft session хранит device/binding snapshot через migration `0016_minecraft_serverbridge_trust_0127.sql`.
- Yggdrasil-compatible password authentication остаётся совместимым для старых клиентов, но `/sessionserver/session/minecraft/join` fail-closed требует verified bound device. Сам legacy opaque token больше не является обходом Device Trust.
- Minecraft validate/hasJoined и ServerBridge `validate-join`/`has-joined` повторно проверяют parent session/device/risk. `binding_epoch` mismatch, смена device, revoke/missing device или revoked risk делают credential непригодным; stale attestation и network-risk step-up дают временный deny до восстановления trust.
- Server-side validation намеренно не записывает IP/User-Agent game server как контекст игрока: risk observation происходит на launcher/player requests, а plugin/hasJoined только читает и применяет уже server-authoritative risk state.
- ServerBridge join дополнительно pin-ит `project/profile/channel`; plugin validation отклоняет `channel_mismatch` так же, как project/profile mismatch. Permanent trust failure инвалидирует join record немедленно.
- Velocity/Paper/Purpur получают конкретные trust reasons (`trusted_device_required`, `session_binding_changed`, `device_reattest_required`, `session_step_up_required` и другие) и показывают игроку соответствующее действие вместо общего deny.

### Verification / release gates

- HTTP regression tests покрывают unbound Minecraft denial, успешный bound credential, invalidation после re-bind, live ServerBridge risk deny и channel pinning.
- Minecraft E2E регистрирует реальный Ed25519 trusted-device key и подписывает production registration challenge перед server join; trust enforcement не обходится synthetic device metadata.
- Gate `minecraft-serverbridge-trust-0127.py` подключён к preflight, repository policy и CI и проверяет runtime, persistence, migration, plugin messages и regression coverage.

## 0.12.6 — Session ↔ Device binding + risk integration

`0.12.6` делает связь Never session с trusted device server-authoritative. Каждая session получает persistent `binding_epoch`; registration/re-bind атомарно увеличивает epoch, а Backend сравнивает его и `device_id/device_trust` с каждым access JWT. Поэтому access token, выпущенный до нового bind, больше не может продолжать работать только потому, что сама session ещё active.

### Device-bound refresh

- Refresh привязанной session требует proof текущим registered device key. Canonical `NeverLauncher Session Device Binding v1` payload связывает `user + session + device + binding_epoch` и SHA-256 текущего refresh token; сам refresh secret в подписываемый payload не включается.
- Backend сначала read-only проверяет refresh family/session binding и device signature, и только затем выполняет rotation. Wrong/missing device proof возвращает `428` и не расходует действительный refresh token. Replay уже consumed refresh token по-прежнему компрометирует всю family и отзывает replacement token.
- Desktop подписывает refresh внутри отдельной Tauri IPC-команды `sign_session_refresh`; команда сама строит canonical payload и сверяет local persisted `deviceId`, поэтому React не может использовать её как arbitrary signing primitive. Software Ed25519 и hardware P-256 используют уже зарегистрированный ключ.

### Risk enforcement

- Migration `0015_session_device_risk_0126.sql` добавляет `binding_epoch`, `risk_score`, `risk_action`, `risk_evaluated_at`; API/CLI migration catalogs синхронизированы. Risk actions: `allow`, `step-up`, `reattest`, `revoke`.
- IP/User-Agent drift становится `step-up`; stale hardware attestation — `reattest`; missing/revoked/invalid trusted device и refresh-token reuse ведут к `revoke`. `risk_updated_at` меняется только при изменении решения, поэтому успешный step-up не становится немедленно устаревшим из-за очередной оценки.
- Sensitive handlers через `requireFreshAuth117` теперь проверяют risk action до обычной freshness policy. Step-up очищает network-drift reasons; hardware attestation completion снимает `reattest` после повторной server-side проверки device state.
- E2E покрывает invalidation pre-bind JWT, mandatory bound-refresh proof, wrong-proof non-consumption, refresh replay family compromise, persisted risk decision и secret-free canonical payload. Gate `session-device-risk-0126.py` подключён к preflight, repository policy и CI.

## 0.12.5 — Device Management + Revocation

`0.12.5` превращает существующий device revoke из разрозненной операции в единый production lifecycle. Пользователь видит active/revoked trusted devices, текущее устройство, может переименовать устройство, необратимо отозвать одно устройство или атомарно отозвать все остальные. Администратор получает тот же registry и revoke после fresh phishing-resistant step-up.

### Runtime revocation

- PostgreSQL revoke выполняется одной транзакцией: trusted device становится permanent tombstone, свежая attestation снимается, незавершённые device challenges расходуются, связанные Never sessions, refresh-token families/tokens и Minecraft sessions отзываются. Возвращаются фактические счётчики, а не результат повторного in-memory revoke.
- ServerBridge joins для затронутых Never sessions инвалидируются немедленно. Access JWT перестаёт проходить session observation после server-side revoke; refresh family также больше не может ротироваться.
- `POST /api/v1/auth/devices/{deviceId}/revoke` и `POST /api/v1/auth/devices/revoke-others` дают явный management API; прежний `DELETE` сохранён как совместимый revoke. `revoke-others` разрешён только session, уже связанной с active verified trusted device, и сохраняет именно это текущее устройство.
- Revocation необратим для прежнего device key/fingerprint: повторная регистрация отозванного ключа запрещена, повторный revoke идемпотентен. Для повторного подключения установка должна создать новый device key.

### Clients / operations / gates

- Desktop показывает trusted-device registry, current/revoked state, rename/revoke/revoke-others. При self-revoke удаляются локальный device key и сохранённая auth session из OS secure storage.
- Admin UI показывает trusted devices и выполняет permanent revoke через защищённый admin endpoint; критическая операция остаётся за fresh phishing-resistant step-up.
- HTTP E2E проверяет challenge invalidation, access/refresh cutoff, tombstone re-enrollment denial, self-revoke и idempotency. `device-management-revocation.py` включён в preflight, repository policy и CI. Новая DB migration не требуется: schema 0.12.4 уже содержит необходимые trusted-device/session/challenge поля; 0.12.5 меняет runtime semantics и transaction boundaries, а не добавляет пустую schema-заготовку.

## 0.12.4 — Challenge-response attestation

`0.12.4` добавляет отдельную рабочую attestation-церемонию поверх hardware-bound identity из `0.12.3`. Backend выдаёт короткоживущий single-use challenge только сессии, которая уже доказала владение зарегистрированным P-256 hardware key и привязана к тому же trusted device. Native Desktop подписывает отдельный canonical `NeverLauncher Device Attestation v1` payload тем же non-exportable platform key; software Ed25519 fallback к этой IPC-команде не допускается.

### Attestation lifecycle

- Добавлены `POST /api/v1/auth/devices/{deviceId}/attest/begin|complete`. Challenge persistent, привязан к `user + device + session + fingerprint + algorithm + binding + provider`, имеет TTL 2 минуты и расходуется атомарно до проверки подписи, поэтому replay и повтор после неверного proof отклоняются.
- Успешный proof сохраняет `attestation_state=verified`, `attestation_method=challenge-response-v1`, `attested_at`, `attestation_expires_at` и device assurance `challenge-response-attested`. Freshness window — 12 часов; после истечения API/JWT эффективно возвращаются к `proof-of-possession`, пока ceremony не выполнена снова.
- Access JWT и `/api/v1/auth/device-trust` отражают свежий attestation state. Это диагностический device assurance: он не повышает RBAC, MFA/auth strength и не считается phishing-resistant user authentication.
- Desktop автоматически выполняет attestation после registration/session-bind только для `p256/hardware`. Новый native `attest_device_payload` принимает исключительно canonical attestation payload, сверяет user/device/fingerprint/provider и не имеет software/create fallback.

### Security boundary / persistence

- Migration `0014_challenge_response_attestation_0124.sql` добавляет persistent attestation state/freshness, расширяет допустимый device assurance и разрешает purpose `attest` в существующем single-use challenge registry. Backend и CLI catalogs byte-identical.
- Challenge-response подтверждает свежое владение уже зарегистрированным hardware-bound key. Текущий platform signer не предоставляет NeverLauncher проверяемый vendor TPM quote / Secure Enclave attestation certificate, поэтому `hardwareProvider` не объявляется remote provenance; API явно возвращает `hardwareProvenance=not-remotely-verified`.
- HTTP E2E проверяет success, unbound-session rejection, replay, wrong-signature consumption и software-key rejection. Новый offline gate `challenge-response-attestation.py` включён в preflight и CI.

## 0.12.3 — Hardware-bound identities

`0.12.3` добавляет реальный hardware-backed device-key path поверх Device Trust Core. Desktop сначала пытается создать non-exportable P-256 signing key в platform hardware provider (Secure Enclave / TPM). Если platform signer сообщает keyring/software/test backend, он не считается hardware-bound: клиент явно остаётся на существующем Ed25519 + OS secure storage пути.

### Hardware identity lifecycle

- Tauri использует pinned `hardware-enclave 0.2.10` и P-256 ECDSA. Hardware private key не сериализуется в NeverLauncher metadata/keyring record и не пересекает IPC; сохраняются только public SEC1 key, SHA-256 fingerprint, provider name и platform key label.
- Device Trust protocol теперь принимает `ed25519/software` и `p256/hardware`. Для P-256 Backend проверяет uncompressed SEC1 public key и raw IEEE P1363 `r||s` signature над тем же canonical single-use challenge payload.
- Hardware key автоматически используется в registration/session-bind flow официального Desktop. Если HSM недоступен, fallback остаётся явным `keyBinding=software`, без ложного hardware status.
- Delete/reset удаляет platform hardware key и локальную metadata; existing `0.12.2` Ed25519 records автоматически продолжают работать как software-bound identities.

### Server boundary / migration

- Добавлена migration `0013_hardware_bound_identities_0123.sql`: `trusted_devices.key_binding`, `hardware_provider`, поддержка `key_algorithm=p256`, relational CHECK constraints и индекс по binding state. Backend/CLI catalogs byte-identical.
- Access JWT содержит диагностические `device_key_binding` и `device_hardware_provider` для уже verified device. Эти claims **не** используются для RBAC, MFA strength или step-up decisions.
- `keyBinding=hardware` в `0.12.3` означает локально выбранный non-exportable hardware provider, но ещё не remote attestation. Поэтому server-side `assurance` остаётся `proof-of-possession`. TPM/Secure Enclave attestation/challenge-response verification является отдельным следующим Device Trust этапом.

### Release gates

- HTTP E2E выполняет реальный P-256 registration + second-session bind и проверяет, что hardware metadata не повышает assurance.
- Добавлен `hardware-bound-identity.py`; preflight/repository policy/CI требуют HSM path, P-256 verifier, migration `0013`, запрет keyring/software promotion и Linux TPM build dependency.

## 0.12.2 — Device keys + OS secure storage

`0.12.2` переводит Device Trust из server-only proof API в рабочий Desktop lifecycle. Официальный Tauri-клиент сам создаёт Ed25519 device key, хранит private seed только в native OS credential store и автоматически выполняет registration/session-bind proof после Never login.

### Device key lifecycle

- Добавлен Tauri-модуль `device_keys`: Ed25519 key generation через OS CSPRNG, deterministic per-backend/per-user keyring namespace, self-check public key/fingerprint и zeroization временного seed/serialized secret.
- Windows использует native credential manager, macOS — Keychain, Linux — Secret Service через `keyring`; plaintext/file/localStorage fallback отсутствует.
- Private key не передаётся React и Backend. IPC возвращает только public key/fingerprint/device id и detached signature конкретного server challenge.
- Auth session record получил canonical `userId`, чтобы device key namespace не зависел от изменяемого email. Старые сохранённые sessions восстанавливают `userId` из уже проверенного JWT `sub`.
- После login Desktop автоматически выполняет `register/begin → local Ed25519 sign → register/complete`; на следующих sessions используется `verify/begin|complete`. Обновлённый verified-device access token атомарно заменяется в OS credential store.
- Если локальная привязка указывает на отозванный/удалённый server device, Desktop создаёт новую local device identity. Fingerprint conflict после прерванной регистрации также fail-closed разрешается новой key pair, а не повторным использованием неизвестной server binding.
- Logout удаляет session secrets, но сохраняет device key для следующего proof-of-possession.

### Release gates

- Добавлен `scripts/smoke/offline/device-key-storage.py`; обычный preflight проверяет наличие native key generation/keyring/signing path и запрещает появление private device key material в React/localStorage.
- Repository policy закрепляет Tauri commands и automatic Desktop proof flow как обязательную часть `0.12.2`.
- `proof-of-possession + OS secure storage` всё ещё не объявляется hardware-bound identity: TPM/Secure Enclave/Windows Hello/Keychain access-control attestation относятся к следующим Device Trust этапам.

## 0.12.1 — Device Trust Core + device registry

`0.12.1` вводит первую рабочую границу Device Trust поверх стабильного Auth Federation release. Старое поле session `deviceId` остаётся недоверенной клиентской меткой для совместимости; доверенная device identity создаётся только после Ed25519 proof-of-possession и хранится отдельно в persistent registry.

### Device registry / proof-of-possession

- Добавлен persistent `trusted_devices` registry с canonical `device id → user`, Ed25519 public key, SHA-256 fingerprint, platform/client metadata, status/trust state, first-class revoke metadata и timestamps последней успешной криптографической проверки.
- Регистрация устройства — реальная challenge-response ceremony: Backend создаёт short-lived single-use challenge, клиент подписывает канонический payload Ed25519 private key, Backend проверяет подпись и только после этого создаёт trusted device. В БД хранится только public key; private key никогда не передаётся Backend.
- Challenge хранится persistent в `device_challenges`, привязан к `user + device + purpose + session`, расходуется атомарно и не может быть replayed. Истёкшие/старые consumed challenges очищаются при записи новых.
- `assurance=proof-of-possession` сознательно не называется hardware-bound: привязка к TPM/Secure Enclave/OS secure storage относится к следующим Device Trust версиям.

### Session binding / revocation

- `auth_sessions.device_id` не переосмысляется как trusted identity. Добавлены отдельные `trusted_device_id`, `device_trust_state` и `device_verified_at`.
- После регистрации или повторного proof текущая Never session криптографически связывается с registry device. Обновлённый access JWT получает `device_id`, `device_trust` и `device_verified_at`.
- Повторная сессия может доказать владение уже зарегистрированным device key через `verify/begin|complete`; challenge дополнительно привязан к конкретной Never session.
- Revoke устройства переводит device в `revoked` и отзывает все связанные Never sessions и refresh-token families; связанные session risk state становятся `compromised`.
- Пользователь может list/rename/revoke свои устройства, администратор — фильтровать registry и выполнять revoke после свежего phishing-resistant step-up.

### Migration / release gates

- Добавлена migration `0012_device_trust_core_0121.sql`: `trusted_devices`, `device_challenges`, session trust columns, relational FK/check constraints и индексы.
- Backend и CLI migration catalogs содержат byte-identical `0012`.
- HTTP E2E проверяет login → registration challenge → Ed25519 proof → trusted session → second-session proof → challenge replay rejection → device revoke → session/refresh-family invalidation.
- OpenAPI и repository policy считают device registry, proof path и migration обязательными `0.12.1` release gates.

## 0.12.0 — Auth Federation Release

`0.12.0` завершает линию Auth Federation `0.11.1–0.11.10` как стабильный production release. Local, SQL, HTTP, OIDC и Microsoft являются providers одного Federation Core; passkeys/TOTP/recovery применяются как auth methods/MFA поверх canonical Never user, а Minecraft Auth Adapter получает уже каноническую Never session независимо от источника входа.

### Stable federation boundary

- Production startup использует стабильный `NewFederationCore(...)`; versioned constructors оставлены только для source compatibility. Встроенный `local` provider теперь проходит тот же Connector SDK conformance gate, что SQL/HTTP/OIDC/Microsoft.
- Добавлены provider-agnostic explicit-link endpoints `POST /api/v1/auth/providers/{providerId}/link/begin|complete`. Любой `browser-auth` connector может быть связан с уже аутентифицированным Never user по доказательству provider identity; совпадение email не является доказательством и не запускает auto-link.
- `GET /api/v1/admin/auth/federation/status` показывает health/capabilities/provisioning policy и количество linked identities для каждого provider. `/ready` дополнительно проверяет, что в registry есть хотя бы один реально здоровый authentication provider.
- External provider token остаётся только server-side credential: он не становится Never access/refresh token и не возвращается из linking/login API.
- Session issuance больше не создаёт `local` identity как побочный эффект. Passwordless passkey создаёт canonical session с `provider=passkey` и без фиктивной `identity-local-*`; MFA continuation после SQL/HTTP/OIDC/Microsoft сохраняет исходные provider/identity. Local identity принадлежит только реальному local-password lifecycle.

### Release migration / canonical local identity

- Добавлена migration `0011_auth_federation_release_0120.sql`. Она backfill/normalize canonical `local` identities для password-capable users и fail-closed отклоняет non-canonical provider/subject values.
- PostgreSQL constraint triggers гарантируют invariant: пользователь с локальным password hash обязан иметь `local` identity с `subject == user.id`; такую identity нельзя удалить/повредить, пока пароль активен.
- Bootstrap admin и `SetUserPassword` теперь транзакционно создают/обновляют local identity. Это закрывает обход Federation Core для первоначальной установки и для добавления локального пароля external-only пользователю.
- Backend и CLI содержат byte-identical migration catalog `0001–0011`; PostgreSQL federation E2E дополнительно проверяет применение `0011` и local-identity invariant.

### Stable release gates

- Federation E2E больше не привязан к конкретной milestone-версии: report schema стабилизирован отдельно от `toolVersion`, поэтому тот же gate применяется к `0.12.x` без изменения тестовой семантики.
- Release matrix включает generic explicit linking/runtime provider health наряду с Local/SQL/HTTP/OIDC/Microsoft/passkey, refresh replay, multi-instance PostgreSQL и Minecraft session exchange.
- OpenAPI и repository policy проверяют stable federation routes, canonical registry и release migration как обязательные `0.12.0` gates.

## 0.11.10 — Federation E2E + migration + stabilization

`0.11.10` не добавляет новый authentication provider: релиз превращает Federation Core `0.11.2–0.11.9` в исполняемо проверяемый release gate. Local, SQL, HTTP, OIDC, Microsoft и passkey проходят одну canonical session/Minecraft matrix; production PostgreSQL E2E проверяет restart/multi-instance refresh/revoke/replay, а migration tooling теперь fail-closed обнаруживает downgrade, checksum drift и незапечатанные legacy migration records до изменения схемы.

### Federation release gates

- `scripts/test/federation-e2e.py` запускает реальную connector/federation matrix: Local, SQL, HTTP, OIDC, Microsoft, passkey, canonical/JIT identity rules, Minecraft session exchange и security failure cases. Это release test, а не manifest/endpoint declaration.
- `e2e/scripts/run-federation-postgres-e2e.sh` поднимает PostgreSQL/Redis и три Backend instances. Test выполняет login на A, restart A, refresh после restart, refresh на B, validation на C, replay старого refresh token на C и проверяет отзыв family на A/B/C.
- CI запускает обе матрицы; strict preflight дополнительно включает PostgreSQL multi-instance E2E через `NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES=1`.
- Federation provider registry больше не сообщает устаревшую внутреннюю версию: runtime metadata использует текущую `VERSION`.

### Migration / upgrade stabilization

- Добавлена migration `0010_federation_stabilization_01110.sql`. Перед добавлением constraints она fail-closed проверяет существующие session/refresh/provider-credential данные; повреждённая БД не «лечится» молча.
- Усилена целостность refresh-token families: допустимые state значения, не более одного `current` refresh token на family, согласованность `session/user/family` и deferrable consistency foreign keys для транзакционной rotation.
- Provider credentials теперь дополнительно связаны composite FK с canonical `auth_identity`, поэтому credential не может принадлежать другому user/provider/subject.
- `nl db migrate apply` сначала проверяет unknown/future migrations и checksum drift. Blank checksum старой известной migration может быть безопасно запечатан текущим embedded checksum; несовпадающий checksum блокирует upgrade.
- Добавлен `nl db migrate verify`: проверяет, что schema полностью применена, нет unknown migrations, нет blank checksum и каждый checksum совпадает с binary catalog.
- Backend migration status возвращает `compatible`, `unknown` и `unverified` наряду с current/pending, чтобы upgrade tooling мог отличить pending upgrade от unsafe schema state.
- Embedded CLI и Backend migration catalogs остаются byte-identical; repository policy проверяет это как release gate.

### Stabilization / failure matrix

- Release matrix отдельно проверяет OIDC issuer/audience errors, HTTP signature/replay/SSRF, Microsoft tenant/signing-key confusion, WebAuthn wrong-origin/challenge replay, SQL disabled/TLS/read-only behavior, refresh replay и canonical identity reassignment protection.
- PostgreSQL E2E делает `db migrate verify` до запуска Backend и после replay/multi-instance сценария, поэтому успешный auth test одновременно подтверждает restart-safe schema state.
- Новых пользовательских auth semantics в `0.11.10` нет: external provider token по-прежнему не является Never token, Minecraft session остаётся дочерней к Never session, а account linking не происходит по одному совпавшему email.

## 0.11.9 — Minecraft Auth Compatibility 2.0

`0.11.9` отделяет Minecraft identity/session от способа входа в NeverLauncher. После local/SQL/HTTP/OIDC/Microsoft/passkey authentication канонический Never user получает persistent Minecraft profile и отдельный opaque Minecraft session token; Minecraft-слой больше не проверяет локальный password hash и не использует Never JWT как игровой access token.

### Minecraft identity / session adapter

- `minecraft_profiles` хранит стабильный UUID, производный только от immutable canonical Never user ID. Email/provider subject не участвуют в UUID; созданное Minecraft name также остаётся стабильным при изменении профиля пользователя.
- `POST /api/v1/minecraft/session` обменивает уже аутентифицированную Never session на отдельную Minecraft session. Opaque `nlmc_*` token хранится только как SHA-256 hash, связан с parent Never session и автоматически перестаёт быть действительным после её revoke/logout.
- Persistent `minecraft_sessions` и short-lived `minecraft_joins` работают между Backend instances. Yggdrasil refresh потребляет старый token; повторный refresh отклоняется. `hasJoined` повторно проверяет Minecraft session и parent Never session и при переданном `ip` проверяет его против join request.
- `profile:launch` достаточно для session exchange: обычный player не нуждается в admin/project-read permission.

### Yggdrasil / Desktop / NeverRuntime

- Реально зарегистрированы `/authserver/authenticate|refresh|validate|invalidate|signout`, `/sessionserver/session/minecraft/join|hasJoined`, profile lookup и `/api/profiles/minecraft/{username}`. Password-capable providers проходят Federation Core; passkey/OIDC/Microsoft используют Never-session exchange.
- Root metadata совместим с authlib-injector. NeverRuntime автоматически добавляет подписанный `authlib-injector*.jar` из release manifest как `-javaagent` к текущему Backend; произвольный локальный JAR таким образом не принимается.
- Desktop перед launch получает Minecraft session и передаёт NeverRuntime реальный UUID/access token вместо `offline` и нулевого UUID. Token редактируется в command preview/diagnostics. ServerBridge join использует то же canonical Minecraft profile name.
- Microsoft sign-in по-прежнему не считается доказательством Minecraft ownership; `0.11.9` реализует Never-managed Minecraft compatibility identity/session, а не Mojang/Microsoft entitlement bypass.
- Встроенная migration chain `nl db migrate apply` синхронизирована с Backend migrations `0001–0009`; repository policy теперь fail-closed проверяет одинаковый набор файлов и SHA-256 содержимого, чтобы manual production upgrade не отставал от Backend auto-migrate.

## 0.11.8 — Session Management 2.0

`0.11.8` переводит Never sessions на полноценный production session-management контур: стандартные JWT/JWS access tokens с `iss`/`aud`/`sub`/`sid`/`jti`/`iat`/`exp`/`kid`/`auth_time`/`amr`, rotation-capable signing keyring, persistent device/risk metadata и пользовательские/административные session controls. Refresh-token family replay по-прежнему отзывает всю family и теперь явно переводит сессию в `compromised`.

### Sessions / risk / controls

- PostgreSQL остаётся source of truth для sessions и refresh families; сохраняются identity/provider, device, first/last IP и User-Agent, auth methods/strength/time, last activity, expiry и risk state.
- Изменение IP или User-Agent переводит активную session в `elevated` и пишет `auth_event`; refresh replay переводит family/session в `compromised` и отзывает её.
- Пользователь может просматривать sessions, переименовывать устройство без изменения device ID, отзывать одну session, все остальные или выполнить logout-all. Admin API фильтрует sessions по user/provider/status/risk и умеет массово отзывать user/provider/risk выборку; provider-wide compromise требует свежую phishing-resistant authentication.
- Provider logout отделён от Never logout: поддерживающий revoke connector получает provider credential server-side, credential удаляется после revoke, но Never session остаётся активной до отдельного revoke/logout.

### Access-token key rotation

- Access token теперь compact JWS/JWT `HS256`, а не custom `base64(payload).HMAC`. Header содержит `typ=JWT`, `alg=HS256`, `kid`; verifier проверяет issuer, audience, token use, timestamps, session id и key id.
- `NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON` задаёт keyring `kid -> secret`, `NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID` выбирает signing key. Предыдущий key остаётся verify-only до истечения выпущенных им access tokens, после чего его можно удалить. Старые production-конфиги с одним `AUTH_TOKEN_SECRET` продолжают работать через `primary` key.

## 0.11.7 — Passkeys / WebAuthn + MFA 2.0

`0.11.7` добавляет production WebAuthn/passkeys поверх существующего Federation Core. Passkeys являются реальным authentication method: credentials и одноразовые challenges сохраняются в PostgreSQL, assertion проверяет RP ID/origin/challenge/signature/user verification/sign counter, а password/SQL/HTTP/OIDC/Microsoft login проходит единый MFA policy до выпуска Never session.

### WebAuthn / Passkeys

- Discoverable credentials с `residentKey=required` и `userVerification=required`; поддерживаются ES256, Ed25519 и RS256 COSE keys.
- Registration принимает только `attestation=none`, проверяет RP ID hash, UP/UV, AAGUID, credential ID и COSE public key.
- Passwordless login и passkey continuation для password/federated login используют одноразовые PostgreSQL-backed challenges с TTL 5 минут.
- Session metadata содержит `authMethods`, `authStrength` (`single-factor`/`mfa`/`phishing-resistant`) и `authTime`; refresh сохраняет эту силу, а step-up выпускает новый access token.
- Passkey credential lifecycle: list/rename/revoke, backup flags, transports, `lastUsedAt`, sign counter и recovery-code cleanup при отзыве последнего credential.

### MFA 2.0 / Step-up

- Per-user policy: `optional`, `required`, `phishing-resistant`. TOTP и recovery codes остаются рабочими; passkey может удовлетворить MFA и обязателен для phishing-resistant policy.
- Критические операции используют fresh authentication: release publish/rollback и migrations требуют свежую MFA; package signing, backup restore, user role changes и ServerBridge token rotation требуют свежую phishing-resistant authentication.
- WebAuthn RP ID/origins валидируются fail-closed в production; sensitive passkey/OIDC/Microsoft auth routes используют auth rate-limit bucket.


## 0.11.6 — Microsoft Connector

`0.11.6` добавляет production Microsoft identity connector как специализацию рабочего OIDC Connector/Federation Core, а не отдельный OAuth engine. Поддерживаются Microsoft identity platform v2 Authorization Code + PKCE S256, `common`/`organizations`/`consumers` и single-tenant GUID authorities, global/US Gov/China clouds, tenant-independent issuer validation, JWKS signing-key issuer validation и стабильная canonical identity на основе `tid + oid`. Microsoft login не считается доказательством владения Minecraft.

### Microsoft identity runtime

- Microsoft provider регистрируется через `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE` и проходит discovery/JWKS/health/conformance до открытия API трафику.
- `offline_access` добавляется обязательно для server-side refresh credential lifecycle; app secret берётся только из environment/file.
- Multitenant token проверяется одновременно по `tid`, фактическому tenant-specific `iss` и `issuer` конкретного JWKS signing key; `allowedTenantIds` может дополнительно сузить trusted tenants.
- Stable external subject — `tid:oid`; mutable email/UPN/name используются только как profile attributes и не участвуют в identity ownership.
- Microsoft external groups/roles не становятся Never roles напрямую: повышение возможно только через локальный `roleMappings` policy при JIT provisioning.

### Account linking / provider credentials

- `explicit-only` остаётся default. Authenticated Never user может выполнить `POST /api/v1/auth/microsoft/{providerId}/link/begin` → provider proof → `.../link/complete`; совпадение email не используется для auto-linking.
- Microsoft/OIDC refresh tokens сохраняются только server-side в `provider_credentials` как AES-GCM envelope, привязанный AAD к user/identity/provider/subject. Plaintext provider token не возвращается клиенту и не становится Never access/refresh token.
- `POST /api/v1/auth/providers/{providerId}/credential/refresh` выполняет provider rotation через Connector SDK и fail-closed проверяет неизменность subject. `DELETE .../credential` удаляет локально сохранённый provider credential.
- `POST /api/v1/auth/microsoft/{providerId}/logout-url` строит allowlisted Microsoft front-channel logout URL отдельно от Never logout/session revoke.

### Scope boundary

Microsoft identity и Minecraft ownership/profile намеренно разделены. `0.11.6` не интерпретирует успешный Microsoft sign-in как Minecraft entitlement и не запрашивает Xbox/Minecraft ownership APIs; это остаётся отдельным entitlement/profile verification layer последующих compatibility работ.

## 0.11.5 — OIDC Connector

`0.11.5` добавляет production OIDC federation поверх Connector SDK/Federation Core: OpenID Provider Discovery, Authorization Code + PKCE S256, state/nonce, JWKS key rotation, ID Token signature/issuer/audience/azp/time validation, optional UserInfo merge с обязательным совпадением `sub`, configurable claims mapping, explicit-only/JIT provisioning и browser/desktop begin/complete flow. OIDC transaction stateless и AEAD-защищён, поэтому не требует process-local session map. Provider tokens не используются как Never tokens.

## 0.11.4 — HTTP Connector

`0.11.4` добавляет второй внешний production auth provider поверх Connector SDK/Federation Core: hardened HTTP Connector для существующих CMS/API. `/api/v1/auth/login` и `/api/v1/admin/login` реально маршрутизируют password authentication в удалённый provider по `providerId`; успешный external subject затем проходит обычный canonical identity/JIT flow и получает Never session, а provider token не становится Never token.

### Remote authentication protocol

- Реальные `POST /authenticate`, `POST /refresh`, `POST /resolve`, `POST /logout` и `GET /health`; paths могут быть переопределены только в startup config и всегда остаются относительными к одному `baseUrl`.
- Strict protocol envelope `neverlauncher-http-auth/1`, обязательный `issuer`, стабильный `subject`, bounded identity fields/groups/roles/claims и fail-closed schema decoding.
- `/resolve` обязан вернуть тот же subject, который был запрошен; изменение subject считается provider misconfiguration.
- Remote error statuses преобразуются в typed Connector SDK errors без утечки произвольного текста upstream пользователю.
- HTTP provider поддерживает SDK password auth, user lookup, token refresh и token revoke; conformance проверяет заявленные capabilities при startup.

### Transport security / SSRF protection

- Только HTTPS; redirects и proxy environment отключены. TLS verification обязательна, поддерживаются custom CA и optional mutual TLS client certificate.
- `hostAllowlist` применяется к каждому dial. Connector выполняет DNS resolution сам, валидирует все полученные IP и соединяется непосредственно с уже проверенным IP, сохраняя TLS hostname verification.
- Loopback, private, link-local, shared, multicast, reserved и documentation networks заблокированы по умолчанию; private endpoint требует явного минимального `allowedCidrs`.
- Connect/request/response-header timeout, bounded connection pool, idle timeout и response size limit конфигурируются с безопасными пределами.

### Request/response authenticity

- Каждый request подписывается HMAC-SHA256 по method/path/timestamp/nonce/body SHA-256; secret берётся только из environment variable или secret file, не из provider JSON.
- Каждый response, включая error response, обязан вернуть тот же nonce и valid HMAC над status/timestamp/nonce/body. Используются constant-time comparison, timestamp replay window и consumed-nonce cache.
- Неподписанный, просроченный, повторный или подписанный другим key response отклоняется до разбора identity.

### Federation / production integration

- `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` / `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE` подключены к реальному startup registry рядом с SQL providers; unreachable/misconfigured provider останавливает startup fail-closed.
- `jit` и `explicit-only` используют тот же Federation Core policy: JIT создаёт canonical Never user + `auth_identity`, но не fake local password; совпадение email не даёт implicit linking.
- Production Compose/CLI templates передают HTTP provider config и отдельный HMAC secret environment variable.
- Integration test поднимает настоящий TLS auth service, проверяет HMAC request/response flow и выполняет HTTP provider authentication через `NewFederationCore114` до persistent canonical identity.

## 0.11.3 — SQL Connector

`0.11.3` добавляет первый внешний production auth provider поверх Connector SDK/Federation Core: SQL Connector для PostgreSQL, MySQL и MariaDB. Это не отдельный endpoint/manifest слой — `/api/v1/auth/login` и `/api/v1/admin/login` реально маршрутизируют password authentication в зарегистрированный SQL provider по `providerId`, после чего Federation Core разрешает external subject в canonical Never user и выпускает обычную Never session.

### SQL authentication runtime

- Конфигурация нескольких SQL providers через `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE`; DSN может ссылаться на отдельную secret environment variable через `dsnEnv`.
- Только NeverLauncher-generated `SELECT`: table/column mapping проходит identifier validation, lookup statements подготавливаются при startup, login values передаются bind-параметрами, произвольный SQL из login request не выполняется.
- PostgreSQL, MySQL и MariaDB; connect/query timeout, bounded pool, connection lifetime, startup health check и fail-closed registration.
- TLS включён по умолчанию для внешнего SQL provider; режимы с plaintext fallback (`sslmode=prefer`, `tls=preferred`) запрещены при `requireTls=true`, insecure certificate verification и plaintext требуют разных явных opt-in.
- Каждый lookup выполняется в read-only transaction и возвращает не более одной identity; ambiguous username/email блокируется как conflict.
- Mapping: external id, username, email, display name, status, groups, roles и Minecraft UUID; groups/roles понимают JSON arrays, comma-separated values и PostgreSQL `text[]`.

### Password compatibility

- Argon2id PHC verification с bounds на memory/time/parallelism.
- bcrypt с ограничением допустимого work factor.
- PBKDF2-SHA256 (включая Django-style format) с минимальным iteration policy.
- Legacy SHA-256 выключен по умолчанию и требует `allowLegacySha256=true`.

### Federation / provisioning

- SQL provider может работать в `explicit-only` или `jit` provisioning mode.
- `jit` после успешной SQL password verification атомарно создаёт canonical Never user + external `auth_identity`; исходная пользовательская таблица остаётся read-only и не мигрируется в NeverLauncher.
- Canonical user ID стабильно выводится из `(provider, subject)`, а не из email.
- Совпадение внешнего email с уже существующим Never user не используется для auto-linking и завершается conflict, требуя явной связи identity.
- JIT federated user не получает фиктивный local-password identity.

### Production hardening

- Docker build теперь копирует `go.sum` и публичный `services/api/pkg`, поэтому production image действительно собирает Connector SDK/Federation Core.
- Добавлены executable tests на prepared/bound queries, read-only transaction, PostgreSQL arrays, TLS fallback policy, duplicate identity detection, Argon2id/bcrypt/PBKDF2/legacy password compatibility, JIT provisioning и запрет email auto-linking.
- Unknown identifier выполняет algorithm-equivalent dummy password work; identifier/password имеют верхние bounds, чтобы снизить timing enumeration и resource-abuse поверхность.
- PostgreSQL JIT provisioning сериализуется transaction-scoped advisory lock по normalized email, поэтому case-insensitive email conflict остаётся fail-closed и при конкурентных первых входах.

## 0.11.2 — Connector SDK + Federation Core

`0.11.2` переводит рабочий local password login на общий Federation Core. Встроенный `local` provider использует тот же публичный Connector SDK, который предназначен для SQL/HTTP/OIDC/Microsoft connectors следующих релизов; прямой password-check в `/auth/login` и `/admin/login` больше не является отдельным auth engine.

### Connector SDK

- Добавлен импортируемый Go SDK `services/api/pkg/authconnector` с typed metadata, capabilities, canonical provider identity, password/browser auth, refresh, profile resolution, identity linking и revoke interfaces.
- Capabilities являются исполняемым контрактом: registry и conformance suite отклоняют connector, который заявляет capability без соответствующего интерфейса.
- Добавлен reusable `authconnector/conformance` testkit; встроенный `local` connector проходит его в backend test suite.
- Connector errors имеют стабильные typed codes (`invalid_credentials`, `identity_disabled`, `unavailable`, `conflict`, `identity_not_found`) вместо сравнения строк ошибок.

### Federation Core

- Добавлен concurrent-safe provider registry и единый password-auth dispatch. `providerId` поддерживается в canonical `/api/v1/auth/login` и `/api/v1/admin/login`; отсутствие значения означает `local`.
- После успешной проверки credentials provider возвращает только authentication proof/identity. Federation Core обязательно разрешает `(provider, subject)` через `auth_identities` в canonical Never `User`; provider token не становится Never access token.
- Реализовано explicit-only identity linking с защитой от silent reassignment одного subject другому Never user.
- Локальный provider теперь реально зарегистрирован через SDK и обслуживает production login. MFA, RBAC, access/refresh sessions и audit выполняются после canonical identity resolution.
- Новые users при создании получают persistent `local` identity; successful federation login обновляет snapshot claims и `last_authenticated_at`.

### Persistence / API

- Migration `0005_federation_core_0112.sql` расширяет `auth_identities` provider metadata (`email`, `username`, `display_name`, `claims`, `last_authenticated_at`) и backfill-ит локальные identity.
- Repository получил рабочие get/list/save/touch операции для canonical identities в memory и PostgreSQL implementations.
- `GET /api/v1/auth/providers` показывает реально зарегистрированные providers/capabilities/health до login; `GET /api/v1/auth/identities` возвращает identity links текущего Never user без provider secrets/claims.
- OpenAPI login schema получил `providerId`; canonical auth capabilities теперь объявляют активный Federation Core и registry providers.

### Verification

- Backend integration test проверяет provider discovery, local login через Federation Core, canonical identity endpoint и дальнейший session refresh/revoke flow.
- Federation unit tests проверяют canonical resolution и fail-closed отказ для authenticated, но не связанной external identity.
- SDK conformance tests проверяют соответствие capability interfaces и health contract.

## 0.11.1 — Auth Core hardening + persistent sessions

`0.11.1` переводит authentication state с process-local registry/snapshot semantics на нормализованный PostgreSQL auth core и закрывает replay refresh token на уровне token family.

### Persistent session core

- Добавлена migration `0004_auth_core_0111.sql` с `auth_sessions`, `refresh_token_families`, `refresh_tokens`, `auth_identities`, `mfa_methods`, `recovery_codes` и `auth_events`.
- В PostgreSQL-режиме login/refresh/active/revoke/list используют общую БД как source of truth; memory backend остаётся только для dev/test.
- Refresh-token rotation сохраняет consumed-token history. Повторное использование старого token помечает family как compromised, отзывает текущий token и всю session.
- Ограничение числа сессий применяется транзакционно и отзывает соответствующие token families.
- Старые 0.10.x persistence snapshots мигрируются в нормализованные auth tables при первом запуске после обновления.

### MFA persistence

- TOTP state вынесен из общего runtime snapshot в `mfa_methods`; TOTP secrets хранятся encrypted at rest.
- Recovery codes хранятся отдельно в `recovery_codes` как hashes и потребляются атомарным `UPDATE ... WHERE status='active'`.
- Несколько Backend instances читают единое MFA/session state непосредственно из PostgreSQL.
- `currentCodeForSmoke` удалён из production enrollment response; тест получает enrollment secret и сам вычисляет код.

### Verification

- Добавлен regression test на refresh-token replay: replay старого token обязан отозвать session и отклонить ранее выданный current token.
- Offline backend test suite проходит с `neverlauncher_nopgx`; production pgx test в изолированном окружении требует заранее доступный module cache/registry.

## 0.11.0 — Minecraft Compatibility Release

`0.11.0` завершает compatibility-линию `0.10.1`–`0.10.7` и переводит её в release-grade состояние: Compatibility Engine, Managed Java, Vanilla/Fabric/Quilt/Forge/NeoForge materializers, actual Minecraft Client E2E и публичная CI-матрица теперь связаны с production release bundle machine-verifiable certification.

### Release-bound compatibility certification

- `nl release build` принимает `--compatibility-matrix`, `--compatibility-targets` и `--source-commit`; matrix повторно валидируется до формирования release checksums.
- В certified bundle добавляются `COMPATIBILITY_TARGETS.json`, `COMPATIBILITY_MATRIX.json` и `COMPATIBILITY_CERTIFICATION.json`.
- Certification требует совпадение product version/commit/run ID, exact target set, PASS всех required targets, `exitCode=0`, mandatory actual-client checks, immutable resolved loader versions и валидный `evidenceSha256`.
- Target definition и matrix хешируются SHA-256; certification фиксирует их digests, required/passed target sets и loader families.
- Все compatibility artifacts входят в `RELEASE_MANIFEST.json` как required, попадают в `SHA256SUMS` и защищаются общей Ed25519 release signature.
- `release verify` продолжает проверять cryptographic integrity candidate bundle; `release publish-check` для `0.11.0+` дополнительно fail-closed требует валидную compatibility certification.
- `scripts/release/build-release.sh` умеет собирать certified bundle через `NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE` + exact `NEVERLAUNCHER_SOURCE_COMMIT`; без matrix он явно создаёт только CI release candidate.

### Compatibility release hardening

- `release doctor` проверяет compatibility target definition и наличие public compatibility workflow/tooling.
- Runtime matrix сообщает release-bound certification как реализованную capability.
- Repository policy закрепляет обязательность certification primitives и предотвращает возврат к publish без фактического matrix evidence.
- Восстановлен отсутствовавший во входном `0.10.7` `runtime/neverruntime/src/bin/neverruntime.rs`; clean Cargo binary target снова имеет source file.
- Исторический hardening `0.10.7` сохранён: exclusive materialization lock, bounded retry, symlink-safe tree, deterministic generated state и строгий CI evidence.

## 0.10.7 — Compatibility stabilization

`0.10.7` стабилизирует весь Minecraft compatibility-контур `0.10.1`–`0.10.6` без добавления нового loader API: исправлены реальные гонки materialization, transient upstream failures, symlink/path escape, stale generated natives, portable atomic replacement и более строгая проверка CI evidence.

### Materialization lifecycle

- Vanilla/Fabric/Quilt/Forge/NeoForge CLI materializers теперь берут exclusive lock на конкретный `clientDir`; параллельная сборка одного дерева не может одновременно перезаписывать metadata/libraries/assets/processors.
- Stale lock старше двух часов безопасно вытесняется; обычное ожидание ограничено и завершается явной ошибкой вместо повреждения client tree.
- `clientDir` и существующие компоненты destination path проверяются через `Lstat`; symlink-компоненты отклоняются до записи.
- Asset logical paths валидируются до materialization virtual/resources tree.
- `buildClientPackage` теперь fail-closed отклоняет symlink artifacts, а не следует за ними при hashing.

### Download / filesystem hardening

- Все Minecraft/loader HTTP GET получили bounded retry для transient `408/425/429/500/502/503/504` и сетевых ошибок; `Retry-After` учитывается с верхним пределом.
- Client artifact ограничен 2 GiB и читается через `limit+1`, поэтому oversized response обнаруживается, а не молча обрезается.
- Повреждённый существующий artifact заменяется portable atomic sequence, работающей и там, где `rename` не заменяет destination напрямую.
- `natives/<os>` полностью пересобирается перед extraction, поэтому stale native libraries предыдущей materialization не попадают в новый signed package.
- Forge/NeoForge installer `data/` очищается и пересоздаётся перед processor execution.

### Runtime / CI evidence

- Compatibility Engine в NeverRuntime отклоняет symlink-компоненты при чтении metadata/classpath paths.
- Убран двойной `java -version` при проверке cached Managed Java.
- Восстановлен обязательный `runtime/neverruntime/src/bin/neverruntime.rs`; repository policy теперь блокирует Cargo `[[bin]]` без source-файла.
- Compatibility matrix aggregator теперь дополнительно требует `exitCode == 0`, healthy Paper evidence, совпадающий `manifestLoader` и полный набор обязательных evidence files.
- Добавлены regression tests для retry, materialization lock, symlink escape, unsafe asset paths, portable replace и symlink package artifacts.

## 0.10.6 — Public CI Compatibility Matrix + hardening

`0.10.6` расширяет actual Minecraft Client E2E до публичной CI-матрицы Vanilla/Fabric/Quilt/Forge/NeoForge и делает результаты machine-verifiable вместо ручной таблицы.

### Public compatibility matrix

- Добавлен canonical `compatibility/targets.json` без PASS/FAIL state; цели валидируются до построения dynamic GitHub Actions matrix.
- Новый `.github/workflows/compatibility.yml` запускает actual-client E2E на `main`, nightly и вручную, публикует per-target evidence и агрегированный `matrix.json`/`matrix.md` в Actions Summary/artifact.
- `scripts/compatibility/matrix.py` fail-closed проверяет completeness, duplicate/missing targets, exact commit/run ID, Minecraft/loader/OS/arch и concrete loader version; mutable `latest-stable` не принимается как resolved result.
- Добавлены regression tests агрегатора для валидного evidence, mutable resolved loader и commit mismatch.

### Generic actual-client E2E

- `run-minecraft-e2e.sh` теперь выполняет тот же production path для Vanilla, Fabric, Quilt, Forge и NeoForge; loader/profile больше не hard-coded как Vanilla.
- Compatibility mode поднимает обязательный Paper node и выполняет materialize → package verify → canonical API upload → signed immutable publish → clean sync → actual Minecraft → world join → revoke/deny.
- Concrete loader version извлекается из materialized package и повторно сверяется с опубликованным signed manifest.
- Исправлена 0.10.5 проверка manifest, где `jq` использовал не переданный `$mc`; в 0.10.6 Minecraft/loader/version передаются явно и проверяются fail-closed.

### Hardening

- `publish-client-package.py` запрещает symlink-компоненты package path и использует strict root containment перед чтением artifact.
- Compatibility result формируется wrapper-ом даже для failed E2E и содержит обязательные evidence checks; агрегатор не доверяет job name или ручному status.
- Repository policy запрещает manual PASS в target definition, требует public workflow/aggregator и generic actual-client primitives.
- Восстановлен `runtime/neverruntime/src/bin/neverruntime.rs`, отсутствовавший во входном архиве 0.10.5 при объявленном Cargo binary target.

## 0.10.5 — настоящий Minecraft Client E2E

`0.10.5` заменяет Java fixture в главном production E2E на реальный Minecraft Java Client и делает фактический вход клиента на сервер блокирующим release gate.

### Real client pipeline

- E2E материализует Minecraft 1.21.1 из официального Mojang `version_manifest_v2`, включая client JAR, libraries, assets, natives и logging config.
- Полученное дерево проходит полный локальный `nl client verify` до публикации.
- Новый `e2e/scripts/publish-client-package.py` повторно SHA-256-хеширует каждый artifact, загружает полный package через канонический `/api/v1`, сверяет backend checksum/size и публикует Ed25519-signed immutable release.
- NeverRuntime скачивает опубликованный release в чистый client root и повторно проверяет pinned Ed25519 signature и SHA-256 всех файлов.
- Настоящий Mojang client запускается под Xvfb/software OpenGL с `--quickPlayMultiplayer` и подключается к настоящему Paper 1.21.1.
- Release gate требует одновременно `neverlauncher.join.allowed username=E2EPlayer` и серверную строку `E2EPlayer joined the game`; простого protocol handshake недостаточно.
- После отзыва launcher session повторная попытка входа проверяет fail-closed deny; Velocity/Purpur сохраняют дополнительное protocol-level bridge покрытие.

### NeverRuntime

- Восстановлен фактический binary source `runtime/neverruntime/src/bin/neverruntime.rs`, который отсутствовал в переданном `0.10.4`, несмотря на объявленный Cargo `[[bin]]`.
- Добавлен `launch_with_timeout` и CLI-флаг `--max-runtime-seconds`: runtime корректно завершает дочерний game process после ограниченного CI-интервала и возвращает `timedOut` в JSON result. Обычный production `launch()` сохраняет прежнее поведение без timeout.
- Размер tail runtime log для launch evidence увеличен до 512 KiB.

### CI

- Production E2E job переведён на 90 минут и устанавливает Xvfb/OpenGL/X11/audio runtime, необходимый настоящему клиенту Minecraft на Ubuntu runner.
- CI artifact теперь содержит materialization verify, опубликованный package, signed manifest, clean sync result, actual Minecraft launch result и health/bridge diagnostics.

## 0.10.4 — Forge + NeoForge

`0.10.4` добавляет рабочую materialization-цепочку Forge и NeoForge поверх `0.10.3` Fabric + Quilt. Реализация использует настоящий processor-based installer format, а не декларативный install-plan.

### Forge / NeoForge installer pipeline

- Добавлены `nl runtime forge-install`, `forge-package`, `neoforge-install`, `neoforge-package`.
- Версия Forge выбирается по official Maven metadata для конкретной Minecraft-версии; NeoForge фильтруется по соответствующей ветке `major.patch`.
- `latest-stable` разрешается в concrete loader version до формирования release.
- Official `installer.jar` скачивается по HTTPS и проверяется по Maven `.sha1`; custom mirror требует явный URL/checksum.
- Installer JAR реально разбирается: читаются `install_profile.json` и встроенный `version.json`.
- Встроенный `maven/` извлекается безопасно в `libraries/`; traversal и symlink отклоняются.
- Installer `data/` извлекается во внутреннее `.neverlauncher` состояние и не попадает в итоговый client package.
- Installer/runtime libraries материализуются с SHA-1/size verification; локально созданные processor outputs нормализуются фактическими digest/size.

### Processor Engine

- Выполняются client processors из `install_profile.json` через реальную Java JVM.
- Processor `Main-Class` читается из `META-INF/MANIFEST.MF`; classpath строится из pinned Maven coordinates.
- Реализованы installer variables `{ROOT}`, `{MINECRAFT_JAR}`, `{INSTALLER}`, `{LIBRARY_DIR}`, `{SIDE}` и `data` variables.
- Maven references `[group:artifact:version[:classifier][@ext]]` разрешаются в локальный `libraries/` path.
- `outputs` проверяются по SHA-1/SHA-256; tokenized hash values вида `{PATCHED_SHA}` и quoted digests поддерживаются.
- Уже корректный output позволяет безопасно пропустить processor при повторной материализации.
- Каждый processor имеет timeout; запуск идёт без shell interpolation.

### Runtime integration

- Child Forge/NeoForge `version.json` нормализуется и сохраняется в `versions/<id>/<id>.json`.
- Итоговый profile использует существующий `inheritsFrom` Compatibility Engine без отдельного launch fallback.
- `runtime matrix` теперь объявляет processor-based Forge и NeoForge materializers готовыми.
- Legacy Forge pre-1.13 остаётся явно вне scope `0.10.4`, вместо ложного статуса поддержки.

### Проверки

- Добавлен полный локальный fixture: Vanilla base -> verified installer -> embedded Maven -> processor execution -> output digest -> child profile -> Never client package.
- Отдельно проверяются Forge/NeoForge Maven version selection, несовместимая Minecraft/NeoForge ветка, Maven classifier/extension paths и archive traversal.
- Восстановлен отсутствовавший в входном `0.10.3` binary source `runtime/neverruntime/src/bin/neverruntime.rs`, на который уже ссылался `Cargo.toml`.

## 0.10.1 — Compatibility Engine

0.10.1 переносит разрешение Minecraft launch metadata в исполняемый NeverRuntime и убирает fallback-планы из production runtime path. Compatibility Engine работает по подписанному содержимому immutable release и строит детерминированный план запуска из реального Mojang-compatible `version.json`.

### Исполняемый Compatibility Engine

- NeverRuntime получил отдельный `compatibility` engine: разрешение цепочки `inheritsFrom`, объединение version metadata, Mojang library/rule evaluation, OS/architecture/features rules, ordered classpath, native classifiers, `arguments.jvm`/`arguments.game`, legacy `minecraftArguments`, Java major version и стандартные Mojang placeholders.
- `classpathStrategy=compatibility`/`mojang` теперь используется непосредственно `Desktop -> NeverRuntime -> JVM`: main class, classpath и аргументы берутся из проверенного metadata, а не из перебора всех JAR-файлов.
- Все metadata и classpath paths, которые использует Compatibility Engine, обязаны входить в подписанный release manifest; локальный неподписанный `version.json` или JAR fail-closed блокирует запуск.
- Для multi-platform release NeverRuntime учитывает `targetOs`: чужие OS artifacts не блокируют verify/sync и не попадают в manifest classpath.
- Java constraint из version metadata участвует в pre-launch проверке совместимости JVM вместе с policy manifest.

### Backend / release integration

- `RuntimeLaunch` поддерживает `versionMetadataPath` и feature flags для Mojang rules; при отсутствии явного пути применяется `versions/<minecraftVersion>/<minecraftVersion>.json`.
- Backend проверяет compatibility metadata path на traversal и не публикует compatibility release без обязательного подписанного `version.json`.
- Рекомендуемый launch template и runtime requirements переведены на `classpathStrategy=compatibility` без статического Fabric/mainClass placeholder.

### CLI и runtime binary

- Product runtime commands больше не создают fallback launch plan при отсутствии `version.json`, а loader metadata без `--metadata`/`--installer-profile` отклоняется.
- Восстановлен фактический `neverruntime` binary, требуемый release pipeline и production E2E: `verify`, `sync`, `launch`; добавлена команда `compatibility` для прямого разрешения локального signed client tree.
- Добавлены unit/regression tests для inheritance, Mojang rules/features, Maven paths, placeholders, path traversal и backend publish validation.

## 0.10.0-P3.2v4 — Production hardening

P3.2v4 завершает следующий production-контур рабочим кодом: опубликованные релизы становятся неизменяемыми, client/desktop lifecycle выполняет реальные файловые операции, first-run становится автономным, а key lifecycle и supply-chain metadata получают фактическую криптографическую и dependency-backed реализацию.

### P3.2v4 — immutable/client/desktop/supply-chain

- Published release стал immutable на HTTP и repository слоях: после `published` запрещены upload, manifest/status mutation и повторная публикация; изменение требует новой версии.
- `nl client install/update/verify/repair/cleanup/rollback` выполняют реальный локальный lifecycle: SHA-256/size verification, snapshots, quarantine orphan-файлов, selective repair и rollback предыдущего состояния.
- `nl install first-run` использует встроенную копию canonical `deploy/production`, не зависит от checkout и требует pinned API/Admin image refs (`@sha256:`); CI-policy проверяет синхронность embedded templates.
- `nl desktop package/verify` принимает только существующие native artifacts, фиксирует size/SHA-256 и отклоняет отсутствующие или изменённые файлы.
- `nl security rotate-key/revocation-list/attest` используют persistent Ed25519 key registry, реальные key pairs, отзыв ключей и detached signatures; release verification может учитывать revocation registry.
- SBOM формируется из реальных Go/npm/Cargo/Gradle dependency manifests/locks в SPDX 2.3; provenance формируется как in-toto Statement с SLSA v1 predicate, hashes artifacts/materials и подписывается Ed25519 (`PROVENANCE.json.sig`).
- Production release bundle включает отдельный проверяемый Desktop package и требует signed provenance attestation.

### Безопасность и конфигурация

- Удалён fallback входа администратора через конфигурационный пароль: login принимает только пароль, хеш которого хранится у пользователя. Добавлен regression-test против повторного появления обхода.
- Production-конфигурация валидируется fail-closed до запуска API: PostgreSQL/pgx, сильный token secret, HTTPS public URL, отдельный backup root, storage и явный CORS allowlist обязательны.
- CORS wildcard удалён; preflight незнакомого origin блокируется, разрешённый origin отражается только из allowlist.
- S3 больше не переключается молча на local storage: ошибка инициализации или health-check останавливает Backend API.
- Admin UI больше не предзаполняет логин и пароль администратора.

### Backup и restore

- Backup создаёт реальный PostgreSQL custom dump через `pg_dump`, сохраняет фактические storage-объекты, JSON-снимки состояния и SHA-256 каждого файла в потоковый `tar.gz`.
- Backup хранится в отдельном `NEVERLAUNCHER_BACKUP_ROOT`; архив сначала пишется во временный файл, синхронизируется и атомарно переименовывается.
- `restore-dry-run` безопасно распаковывает архив во временный каталог, запрещает traversal/необычные tar entries, сверяет размеры/SHA-256 и проверяет PostgreSQL dump через `pg_restore --list`.
- Добавлен реальный `POST /api/v1/operations/backups/{backupId}/restore`: PostgreSQL восстанавливается через `pg_restore`, storage — через текущий storage driver. Разрушительная операция требует точного подтверждения `backupId` и явного выбора database/storage.
- CLI `nl backup restore` вызывает реальный restore и требует `--confirm <backupId>` плюс `--database true` и/или `--storage true`.

### Очистка и release gates

- Удалены пять неиспользуемых legacy handler-файлов поколений API 5.4–7.8; используемые общие helpers вынесены отдельно.
- `release doctor` запускает repository policy, version alignment и OpenAPI validation и больше не выдаёт ложный `production-ready`; полный production gate выполняется строгим preflight.
- `NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh` требует pgx, frontend, Tauri, ServerBridge и release bundle и fail-closed останавливается при недоступном обязательном контуре.
- Production E2E использует отдельный `e2e-production`: все production guards остаются включены, HTTP разрешён только для loopback тестового API.

### Production completion поверх hardening

- Docker API image и canonical Compose теперь детерминированно готовят writable storage/backup volumes для непривилегированного UID `10001`; отдельный init-service исправляет ownership существующих named volumes до старта API.
- `release sign/verify` используют настоящий Ed25519 с внешним private/trusted public key. `release verify` fail-closed валидирует каждый required artifact, SHA-256 и signature.
- Pipeline CLI выполняет настоящие Backend `validate → sign → stage → smoke-test → publish` операции; storage audit/consistency сканируют реальные объекты и SHA-256; migrate apply выполняет встроенный migrator, rollback идёт через подтверждённый backup restore; install verify/storage-check реально обращаются к Backend/storage.
- Старый first-run generator удалён: CLI копирует только canonical `deploy/production` template и не генерирует слабые `.env`/пароли.
- Backup/restore защищены maintenance-lock; перед restore создаётся safety backup, local storage переключается атомарным directory rename, PostgreSQL восстанавливается одной транзакцией.
- Source release package переведён на git-tracked/allowlist модель с запретом symlink/secret paths и обязательным secret scan.
- Production release bundle теперь требует реальные Admin Web, Desktop Web/native, NeverRuntime и Velocity/Paper/Purpur Bridge artifacts; CI полностью собирает и криптографически проверяет bundle.

## 0.10.0-P3.2v2 — Нормализация схем и усиление release-gates

P3.2v2 закрывает оставшиеся регрессии после P3.2 без добавления status-only слоёв или архитектурных заглушек.

### Документация и интерфейсы

- Актуальная документация, production checklist, TLS/E2E/smoke-гайды и README компонентов приведены к `0.10.0-P3.2v2` и переведены на русский язык.
- Admin UI и Desktop UI очищены от устаревших `0.10.0`-подписей и основных англоязычных операторских текстов.
- Версия синхронизирована в CLI, Backend, Admin, Desktop/Tauri, NeverRuntime, ServerBridge, deployment и E2E.

### CLI schemaVersion

- Исторические milestone-значения `schemaVersion` 4.x–8.x в CLI заменены на единую `cliSchemaVersion = "1.0"`.
- Специализированные форматы с собственными схемами, включая manifest/runtime, сохранены отдельно и не маскируются версией продукта.

### Preflight и CI

- Добавлен исполняемый `repository-policy.py`, который блокирует возврат CLI `schemaVersion` 4.x–8.x, рассинхронизацию версии, устаревшие docs/UI и известные англоязычные UI-регрессии.
- Policy-gate включён в `scripts/release/preflight.sh` и GitHub CI.
- `version-alignment.sh` расширен проверками NeverRuntime, Gradle ServerBridge, production image tag, E2E и актуальной документации.

## 0.10.0-P3.2 — Canonical API / CLI consistency

P3.1 completes the cleanup started in P3 without restoring compatibility shims or status-only product layers.

### API and implementation cleanup

- Fixed OpenAPI generation/validation after the P3 file renames; the checked-in `/api/v1` contract is generated from the real router and validated 1:1.
- Renamed the remaining `v5_*` implementation files and functions to product/domain names; no `/api/v5` router was reintroduced.
- Removed remaining P1/P2 implementation suffixes from manifest-signing, version-manifest and runtime wiring helpers.
- Canonical package/admin/security responses now point to `/api/v1` resources instead of historical endpoint hints.

### CLI

- Migrated all reachable Backend HTTP calls to `/api/v1`.
- Removed historical `platform`, `product`, `extension`, `public`, `beta`, `registry`, `lts` and standalone `deployment` command families that no longer have product functionality.
- Rewrote `nl --help` around the current install/auth/admin/operations/package/runtime/release surface without historical 4.x–8.x labels.
- First-run/install guidance now uses current installation verification instead of the removed beta-smoke command.

### Tests and documentation

- Converted canonical Backend HTTP checks that were incorrectly stored as production `.go` files into real `_test.go` integration tests.
- Restored active `/api/v1` regression coverage for CRUD, packages, signing, ServerBridge, backup, security and canonical-route enforcement.
- Updated the root README, CLI README, Backend API README and production deployment README for P3.1.
- Renamed release output from `dist/gitflic-release-*` to `dist/release-*` and `GITFLIC_RELEASE_DESCRIPTION.txt` to `RELEASE_NOTES.txt`; active release tooling is hosting-neutral.

## 0.10.0-P3 — Cleanup / Recovery

P3 restores a coherent production tree after repository cleanup without reintroducing historical compatibility/status layers.

### Recovery

- Physically completed the CLI split: the dispatcher `main.go` no longer duplicates domain command implementations.
- Physically completed the Backend split: `server.go` no longer duplicates canonical handlers, trusted-proxy or rate-limit code.
- Historical `/api/v2`–`/api/v5` routers remain removed; real product capabilities are registered under `/api/v1`.
- Restored the single canonical `schemas/openapi.yaml` and 1:1 router/OpenAPI validation.
- Removed preflight/release-script references to deleted fake/RC/stable/GitFlic smoke files.

### P2 production behavior restored

- Desktop uses NeverRuntime directly.
- Native OS credential storage is used for auth session secrets; there is no plaintext token fallback.
- JVM launch is supervised and logs stream to disk instead of buffering the whole process output.
- NeverRuntime downloads and SHA-256 verification are streaming.
- S3 upload uses disk spooling + incremental SHA-256 instead of buffering the object in memory.
- Redis-backed rate limiting, trusted proxies, production Admin image, CSP and production Compose are active again.
- Real Velocity/Paper/Purpur E2E is restored.

### Contracts / tests

- Canonical Backend tests now exercise `/api/v1` for CRUD, package publishing, security hardening, backup and ServerBridge.
- Historical API paths are tested as absent instead of being re-enabled for regression compatibility.

## 0.10.0-P0 — Production P0 Hardening

P0-патч закрывает критические security/database/release-integrity проблемы стабильной 0.10.0 без расширения продуктового API.

### Security

- Bootstrap owner защищён одноразовым `NEVERLAUNCHER_BOOTSTRAP_TOKEN`; plaintext токена не сохраняется в PostgreSQL.
- Состояние установки хранится в `neverlauncher_installation_state`; повторный bootstrap блокируется, после первого проекта фиксируется `installation_completed=true`.
- Mutating admin/release/extension endpoints предыдущих API-поколений требуют действительную session/permission.
- Desktop Launcher fail-closed проверяет Ed25519 manifest signature и точное совпадение pinned public key перед download/repair/build-launch-plan/launch.

### Database

- Добавлен исполняемый production migration runner с `schema_migrations`, SHA-256 checksum и PostgreSQL advisory lock.
- `nl db migrate apply` реально применяет embedded migration chain через `psql`.
- Backend автоматически применяет migrations или при отключённом auto-migrate отказывается стартовать при pending/checksum mismatch; `/ready` проверяет ту же цепочку.
- Baseline миграция нормализует исторические PostgreSQL layouts в текущую SQLRepository-схему и fail-closed останавливается на несопоставимых legacy file rows.

### Release integrity

- Production `build-release.sh` собирает Backend только с pgx и больше не имеет `neverlauncher_nopgx` fallback.
- Неизвестный repository driver больше не приводит к молчаливому переходу на in-memory repository.

### Проверено

- `go test ./...`, `go vet ./...` для CLI.
- `go test -tags neverlauncher_nopgx ./...`, `go vet -tags neverlauncher_nopgx ./...` для offline Backend контура.
- `scripts/release/preflight.sh` проходит для `0.10.0-P0` в offline-контуре.
- Full pgx/Cargo/live PostgreSQL проверки требуют среды с соответствующими зависимостями.

## 0.10.0 — Stable LauncherOps Platform

NeverLauncher 0.10.0 — первый стабильный product-релиз self-hosted LauncherOps Platform для Minecraft-проектов. Релиз фиксирует стабильный контур Backend API, CLI `nl`, Admin UI, Desktop Launcher, ServerBridge для Velocity/Paper/Purpur, production deployment, package delivery, runtime resolver, diagnostics, audit, backup/restore baseline и release gates.

### Добавлено

- Backend API слой Stable Release: `/api/v5/stable-release/status`, `/readiness`, `/components`, `/e2e`, `/artifacts`, `/final-report`.
- CLI-группа `nl stable`: `status`, `readiness`, `components`, `e2e`, `artifacts`, `final-report`, `smoke`.
- Миграция `0103_stable_release_0100.sql`.
- Stable smoke-gate `scripts/smoke/stable-required/stable-release-smoke.sh`.
- Минимальный комплект `schemas/` и `examples/` для GitFlic Release, OpenAPI, package/runtime/project/profile manifests, ServerBridge и extension runtime.

### Изменено

- Версия продукта синхронизирована как `0.10.0` во всех основных компонентах.
- `scripts/release/preflight.sh` включает AdminOps, Security Freeze, RC1, RC2 и Stable Release gates.
- Production deployment использует единые canonical env-переменные: `NEVERLAUNCHER_DATABASE_DSN`, `NEVERLAUNCHER_AUTH_TOKEN_SECRET`, `NEVERLAUNCHER_STORAGE_LOCAL_PATH`, `NEVERLAUNCHER_REDIS_ADDR`.
- Legacy smoke-скрипты приведены к текущей версии 0.10.0 и больше не ожидают 9.x artifacts.
- `SECURITY.md`, `.env.example`, E2E-документация и smoke-документация приведены к релизу 0.10.0.

### Проверено

- `scripts/release/preflight.sh` — обязательный offline release gate.
- `scripts/smoke/docker-required/production-compose-config.sh` — static production compose gate.
- `scripts/smoke/minecraft-required/minecraft-demo-kit-smoke.sh` — static Minecraft E2E demo-kit gate.
- `scripts/test/check-gitflic-publication.sh` — проверка GitFlic Wiki, release example и schema/example комплекта.

### Ограничения

- Native Tauri build требует локальной среды с Rust/Cargo.
- Full PostgreSQL/pgx режим проверяется отдельно через `NEVERLAUNCHER_PREFLIGHT_PGX=1` в среде с доступными Go-зависимостями и PostgreSQL.

## 0.9.13 — Release Candidate 2 / Compatibility Lock

RC2 зафиксировал compatibility policy для Backend API v5, CLI command surface, production config, ServerBridge contract, manifest schemas и SQL migration numbering.

## 0.9.12 — Release Candidate 1

RC1 зафиксировал feature freeze, release candidate gates, compatibility matrix, upgrade checks и release artifacts checklist.

## 0.9.11 — Security Freeze

Security Freeze зафиксировал auth hardening, ServerBridge security, package integrity и production guard.

## 0.9.10 — UX, AdminOps & Operator Experience

Релиз добавил AdminOps, operator flow, diagnostics, backup/restore UX и соответствующий smoke-gate.

## 0.9.9 — Production Deployment & Real E2E

Релиз добавил production compose, nginx contour, first-run bootstrap, Minecraft E2E demo-kit и production E2E endpoints.

## 0.9.8 — Build, Test & Release Gate

Релиз добавил единый `scripts/release/preflight.sh`, smoke-матрицу, GitFlic CI baseline и release-gate discipline.

## 0.9.7 — Release Cleanup & Version Alignment

Релиз синхронизировал версии, подчистил README/Wiki и подготовил ветку к стабильной 0.10.x-линейке.
