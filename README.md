## JVM-Aware Protection — 0.18.8

NeverLauncher 0.18.8 делает executable-memory policy JVM-aware вместо правила «любой перехваченный `VirtualAlloc/VirtualProtect` допустим». Ранний Sensor определяет загруженный HotSpot `jvm.dll`, извлекает его реальный Java major из Windows version resource и допускает aggressive protection только для сертифицированной базы Java `8/16/17/21/25`. Для каждого нового executable `MEM_PRIVATE` transition Hook Engine снимает native call stack без выделений памяти; JIT/Code Cache transition считается доверенным только когда stack содержит frame внутри текущего `jvm.dll`.

Это не запрещает HotSpot JIT и не применяет `ProhibitDynamicCode` к Java: baseline executable private regions сохраняются как раннее JVM состояние, а subsequent JIT transitions учитываются отдельно. `MEM_IMAGE` остаётся под Memory Integrity, thread start origin — под Thread & Process Integrity. Foreign native module, который создаёт executable private memory вне `jvm.dll` provenance, получает отдельный JVM-aware violation и runtime завершается fail-closed. Windows CI проверяет ту же политику на Temurin Java 8/16/17/21/25 реальным JIT workload и adversarial DLL.

## Защита от отладки и instrumentation — 0.18.7

NeverLauncher 0.18.7 закрывает штатные user-mode debug/instrumentation boundaries защищаемой JVM. До spawn NeverRuntime отклоняет сторонние Java/JVMTI agents, JDWP/debug options и instrumentation, пришедшую через стандартные Java option environment variables; затем сам добавляет `-XX:+DisableAttachMechanism`. Внутри JVM ранний Sensor проверяет локальный/remote debugger state и kernel-reported debug port/object/flags каждые 250 мс. Обнаружение debugger attach или противоречивого debug state приводит к fail-closed завершению runtime.

`Agent_OnLoad` теперь требует четыре последовательных authenticated proofs: Hook Engine, Memory Integrity, Thread & Process Integrity и `DEBUG_INSTRUMENTATION_READY`. Runtime report содержит состояние attach hardening, независимые debug indicators, check/violation counters и `stateSha256`. Реализация не скрывает процесс от Windows/EDR и не использует kernel driver или anti-debug bypass primitives.

## Thread & Process Integrity — 0.18.6

NeverLauncher 0.18.6 добавляет непрерывный контроль потоков и дерева процессов защищаемой JVM. `neverguard-sensor.dll` перечисляет live TID, получает их реальный Win32 start address через `NtQueryInformationThread`, проверяет backing memory и origin module; нормальные JVM/GC/compiler threads разрешены, но старт потока из executable `MEM_PRIVATE`/`MEM_MAPPED` memory считается suspicious runtime transition и обрабатывается fail-closed. Проверка выполняется чаще общего heartbeat, чтобы короткое окно между событиями не превращалось в единственную линию защиты.

Внешний NeverRuntime одновременно использует уже обязательный non-breakaway Job Object как process-tree boundary: JVM root и все наблюдаемые descendants должны оставаться членами того же Job Object. Evidence содержит thread/process counts, lifecycle transitions, descendant peak, `threadSetSha256`, `threadOriginSetSha256` и `processTreeSha256`. `Agent_OnLoad` не возвращает управление JVM до третьего authenticated startup proof `THREAD_PROCESS_READY`.

## Memory Integrity — 0.18.5

NeverLauncher 0.18.5 расширяет `neverguard-sensor.dll` непрерывным контролем executable memory внутри защищаемой JVM. Sensor снимает `VirtualQuery` map, хеширует executable `MEM_IMAGE` code regions и на каждом heartbeat проверяет их содержимое и protection state. JVM JIT не ошибочно считается immutable code: executable `MEM_PRIVATE` regions контролируются по startup baseline и наблюдаемым `VirtualAlloc`/`VirtualProtect` transitions от Aggressive Hook Engine. Неизвестная executable private/mapped memory, потеря transition events или code-page drift переводят runtime в fail-closed.

Parent принимает запуск только после двух authenticated proofs: `HOOK_READY` и `MEMORY_READY`. Runtime report содержит executable/image/dynamic/RWX counts, executable bytes, observed transition count, integrity checks, `codeSetSha256` и `executableMapSha256`.

## Aggressive Hook Engine I — 0.18.4

NeverLauncher 0.18.4 добавляет в `neverguard-sensor.dll` ограниченный user-mode hook engine. До запуска Java/Minecraft main Sensor меняет выбранные IAT-импорты в разрешённых JVM/native-модулях для `LoadLibrary*`, `VirtualAlloc` и `VirtualProtect`, проверяет исходную цель как ожидаемый Windows export и отправляет NeverRuntime аутентифицированное доказательство `HOOK_READY`. Глобальные Windows hooks не устанавливаются, память чужих процессов не изменяется.

Покрытие hooks непрерывно пересчитывается при загрузке DLL. Каждый установленный IAT slot проверяется на drift, логический набор hooks хешируется, а tampering обрабатывается fail-closed. При штатной выгрузке Sensor исходные IAT pointers восстанавливаются. Runtime report содержит число hooked modules/slots, количество перехваченных вызовов, integrity checks, SHA-256 набора hooks и нарушения.

# NeverLauncher

## Module Guard — 0.18.3

NeverLauncher 0.18.3 переводит Windows NeverGuard с одних периодических module snapshots на непрерывный контроль DLL внутри JVM. `neverguard-sensor.dll` регистрирует `LdrRegisterDllNotification` до выхода из `Agent_OnLoad`; loader callback не выполняет файловый I/O и не аллоцирует память, а пишет load/unload records в фиксированный atomic ring. Отдельный Sensor worker передаёт ordered HMAC-SHA-256 event stream и heartbeat по уже защищённому Named Pipe. JVM не получает управление Java/Minecraft main, пока parent не снимет внешний ToolHelp baseline и не вернёт authenticated Module Guard arm acknowledgement.

Parent сверяет строгую последовательность и MAC каждого события, хэширует принятые загрузки в rolling event chain и регулярно сопоставляет event-derived module set с независимым ToolHelp snapshot. Windows/Java/runtime roots считаются доверенными runtime boundaries; DLL вне этих roots должна пройти Authenticode. Потеря heartbeat, overflow event ring, sequence/MAC mismatch, неизвестный unload, неподписанная DLL вне roots или snapshot drift завершают JVM fail-closed. Supervised status отдаёт живой `moduleGuard` report с baseline/current module count, load/unload/heartbeat counters, `eventChainSha256`, `moduleSetSha256` и violation state.

0.18.3 остаётся user-mode boundary: administrator/kernel attacker и уже получивший полный arbitrary in-process memory-write примитив противник не объявляются нейтрализованными этим слоем. Module Guard усиливает раннее обнаружение/остановку DLL/module tampering, а memory/hook integrity относятся к следующим этапам NeverGuard.

## NeverGuard Sensor — 0.18.2

NeverLauncher 0.18.2 добавляет реальный Windows JVM sensor как отдельный native `cdylib` — `neverguard-sensor.dll`. Desktop/NeverRuntime добавляет его через `-agentpath` **до пользовательских JVM-аргументов и до Java main**, а JVM вызывает экспортированный `Agent_OnLoad` при старте VM. Sensor обязан выполнить одноразовый HMAC-SHA-256 startup proof через защищённый current-user Named Pipe; proof привязан к protocol version и PID запущенной JVM. Родитель принимает runtime только после проверки proof. При timeout, неверном PID/HMAC или отсутствии Sensor JVM принудительно завершается.

В production Sensor является частью той же Windows release boundary, что Desktop/Guard/Runtime: x64 и ARM64 DLL собираются release pipeline, проходят PE architecture check, подписываются Authenticode/RFC3161 тем же production signing context, входят в `WINDOWS_PACKAGE_MANIFEST`, component-update manifest и signing evidence. Перед `-agentpath` release runtime повторно проверяет, что DLL — обычный непустой файл и её Authenticode trust валиден. `neverguard-sensor.dll` обновляется атомарно вместе с Desktop/Guard/Runtime. Windows CI отдельно собирает DLL и запускает настоящую Temurin JVM с `-agentpath`, затем требует успешный `Agent_OnLoad` handshake.

Эта версия подтверждает раннюю загрузку доверенного Sensor и создаёт in-process security boundary для следующих этапов Module Guard/hooks. Она не заявляет непрерывный anti-tamper, защиту от kernel/administrator attacker или kernel-equivalent guarantees.

## Windows Protection Core II — 0.18.1

NeverLauncher 0.18.1 переводит Windows NeverGuard на исполняемую profile/capability модель. Профили `audit`, `compat` и `aggressive` отличаются фактически применяемыми Windows process mitigations; после `SetProcessMitigationPolicy` Guard считывает состояние обратно через `GetProcessMitigationPolicy`, проверяет реальное membership в launcher Job Object и публикует authenticated capability report через HMAC IPC. Desktop проверяет report до перехода Guard в ready-state.

По умолчанию используется `aggressive`. Профиль можно задать переменной процесса `NEVERGUARD_WINDOWS_PROTECTION_PROFILE=audit|compat|aggressive`; Desktop передаёт выбранное значение в Guard отдельным `--protection-profile`. `audit` предназначен для измерения совместимости, `compat` сохраняет совместимые hardening controls без запрета dynamic code, а `aggressive` требует полный Guard mitigation set и является единственным профилем, допускаемым к remote Guard Attestation. Ни `audit`, ни `compat` не могут выдать себя за high-trust `aggressive`: профиль, required bits, observed bits, capability-model version и Job binding проверяются после authenticated IPC handshake.

## Loader Hardening — 0.17.10

NeverLauncher 0.17.10 усиливает production loader path для Fabric, Quilt, Forge и NeoForge: immutable resolution replay использует content-addressed SHA-256 cache и может восстановить pinned profile/installer без mutable upstream. Повреждённые cache entries quarantined и не принимаются как валидные.

Forge/NeoForge processors ведут durable recovery journal (`running` / `failed` / `completed`) с identity каждого processor и SHA-256 installer. После crash verified outputs восстанавливаются без повторного запуска, а неполные/повреждённые outputs quarantined и processor выполняется заново. Release certification требует cache-only/upstream-independent recovery на четырёх current Linux x64 anchors; Forge/NeoForge дополнительно обязаны доказать installer и processor recovery.

## Cross-platform Loaders — 0.17.9

NeverLauncher 0.17.9 переносит рабочий Fabric/Quilt/Forge/NeoForge client certification на **Windows, Linux и macOS в x64 и ARM64**. Для current anchors (`Fabric/Quilt/Forge 26.3`, `NeoForge 26.2`) обязательны все шесть OS/arch-пар; исторические широкие loader-линии сохраняются как Linux x64 regression-база.

Materializer получает exact target и обязан создать только соответствующее `natives/<os>/<arch>` дерево (`macOS` → Mojang `osx`). NeverRuntime теперь возвращает фактически выбранный `nativesDirectory`; отдельный verifier сверяет его с materializer evidence, проверяет SHA-256 каждого native-файла и формирует `nativeTreeSha256`. PASS также требует реальный запуск loader profile на target Java/OS/arch. Release certification хранит 24 `crossPlatformLoaderTargets`, а bundle verifier повторно вычисляет coverage.

## Loader-native E2E — 0.17.8

NeverLauncher 0.17.8 добавляет обязательный production E2E для **настоящей пары loader client ↔ loader server** на Fabric, Quilt, Forge и NeoForge. Для integration anchor Minecraft 1.21.1 compatibility pipeline сначала разрешает loader в concrete immutable version, затем поднимает отдельный dedicated server того же loader и **той же exact version**, проверяет loader runtime artifacts на сервере и запускает уже materialized NeverLauncher client через NeverRuntime с direct-connect на этот сервер.

PASS требует healthy dedicated server, точного loader artifact, успешного actual-client certification и фактической строки `NeverLauncherCertification joined the game` в server log. Evidence (`loader-native-server.json`, client result, server log/process/artifact list и health) входит в aggregate matrix, release certification хранит четыре обязательных `loaderNativeTargets`, а bundle verifier повторно сверяет coverage. Existing Paper integration/revoke path и 0.17.7 immutable resolution lock остаются обязательными и не заменяются этим тестом.

## Loader Resolution & Pinning — 0.17.7

NeverLauncher 0.17.7 делает разрешение Fabric/Quilt/Forge/NeoForge воспроизводимым: mutable selector (`latest-stable`/`stable`/`recommended`) используется только при первом разрешении, после чего materializer сохраняет immutable resolution lock с concrete loader version, provenance source SHA-256, SHA-256 фактического Meta profile/installer и SHA-256 итогового runtime profile. Повторный materialize с тем же selector обязан воспроизвести тот же lock и те же bytes; изменение upstream payload/profile или lock приводит к fail-closed ошибке.

Compatibility E2E выполняет materialization дважды и требует `resolutionPinned=true`, совпадающие `resolutionLockSha256`/`reproducibilitySha256`, raw `<loader>-resolution-lock.json` и concrete resolved loader version. Release certification переносит эти данные в `loaderPins` и bundle verifier повторно пересчитывает их из embedded matrix/targets, поэтому reproducibility evidence нельзя подменить после сертификации.

## NeoForge Compatibility II — 0.17.6

NeverLauncher 0.17.6 делает **NeoForge 1.20.1 → current stable 26.2** отдельной production compatibility-линией: 22 обязательных targets на exact Java 17/21/25, `1.21.1` остаётся полным integration E2E, остальные версии проходят actual-client certification на Linux x86_64. Для 1.20.1 используется реальная историческая публикация `net.neoforged:forge` (`1.20.1-47.x`); начиная с 1.20.2 применяется `net.neoforged:neoforge`, а 26.x разрешается по полной схеме Minecraft version (`26.2` → `26.2.0.x`).

Client certification выполняет официальный NeoForge installer/processors, проверяет processor outputs, materialized Maven libraries и generated version profile, затем `nl client verify` проверяет package, а NeverRuntime запускает фактический NeoForge profile на exact target Java. PASS требует concrete immutable resolved loader version и raw `neoforge-install.json` / `neoforge-certification.json` evidence; missing/duplicate release, wrong Java/scope/platform или mutable loader блокируют release.

## Forge Legacy 1.7.10 — 0.17.5

NeverLauncher 0.17.5 добавляет отдельный production path для **Forge 1.7.10 LaunchWrapper/FML legacy**. V1 `install_profile.json` разбирается как настоящий legacy installer: universal JAR извлекается из `install.filePath`, проверяется и размещается в Maven tree; `versionInfo` без `inheritsFrom` безопасно нормализуется к Vanilla 1.7.10, сохраняя LaunchWrapper metadata и `cpw.mods.fml.common.launcher.FMLTweaker`. Старый официальный `http://files.minecraftforge.net/maven/` канонизируется только в официальный HTTPS Forge Maven.

NeverRuntime поддерживает legacy native classifier metadata без современного `downloads.classifiers`: путь classifier выводится из Maven-coordinate, а неполные современные classifier maps по-прежнему отклоняются. Обязательная certification-цель — Forge 1.7.10, Java 8, Linux x86_64, package verify и фактический client launch через NeverRuntime с immutable resolved Forge version. Forge 1.12.2 и processor-based Forge 1.13.2+ сохраняют отдельные regression/release gates.

## Forge Legacy 1.12.2 — 0.17.4

NeverLauncher 0.17.4 добавляет отдельный production materializer для **настоящего Forge 1.12.2 legacy installer**. Классический V1 `install_profile.json` (`install` + `versionInfo`) обрабатывается без эмуляции modern processors: universal JAR извлекается из `install.filePath`, публикуется в Maven layout, проверяется по SHA-1, исходный `versionInfo` сохраняется как launch profile, а старые `clientreq`/`checksums` учитываются при client materialization.

Также поддерживается официальный переупакованный 1.12.2 layout с `version.json` и пустыми `data/processors`: embedded universal Maven artifact материализуется через отдельный `legacy-v2-empty-processors` path. Оба режима обязаны дать `net.minecraft.launchwrapper.Launch` + `FMLTweaker`, package integrity и фактический запуск Forge profile через NeverRuntime на exact Java 8. Modern Forge 1.13.2+ остаётся processor-based и не ослабляется.

## Forge Modern — 0.17.3

NeverLauncher 0.17.3 делает **processor-based Forge 1.13.2+ → current** отдельной production compatibility-линией. Обязательная матрица содержит 43 Forge release points `1.13.2`–`26.3` на exact Java 8/16/17/21/25. Client targets выполняют официальный Forge installer pipeline: verified installer.jar, embedded/profile Maven libraries, client processors и их outputs, generated version profile, package integrity и реальный launch через NeverRuntime. `1.21.1` сохраняет полный integration E2E.

Forge installer executor поддерживает spec v1 inline tokens (`{MINECRAFT_VERSION}`, `{INSTALLER}`, `{LIBRARY_DIR}`, `{SIDE}` и installer data/artifact values), требует минимум один client processor и fail-closed отклоняет legacy/non-processor installer. `latest-stable` должен разрешиться в concrete immutable Forge version до PASS.

## Quilt Compatibility II — 0.17.2

NeverLauncher 0.17.2 расширяет production-сертификацию на **Quilt 1.14+ → current**. Обязательная Quilt-линия содержит 48 stable Minecraft release ID от `1.14` до `26.3` с exact Java 8/16/17/21/25. Для client-scope target CI использует официальный Quilt Meta v3, материализует настоящий Vanilla+Quilt client tree и Maven libraries, проверяет package integrity, разрешает `latest-stable` в конкретный immutable Quilt Loader и запускает materialized Quilt profile (`KnotClient`) через NeverRuntime на exact Java. `1.21.1` сохраняет полный integration E2E.

Quilt `latest-stable` теперь fail-closed исключает prerelease Loader (`beta`/`rc`/другой semver prerelease), даже когда Quilt Meta не публикует Fabric-style `stable` flag. Release certification требует всю Quilt-линию и блокирует missing/duplicate releases, неверный Java/scope/platform, mutable resolved Loader, неполное evidence или незапущенный реальный Quilt client. Fabric Compatibility II 0.17.1 и все предыдущие GA/hardening gates сохраняются.

## Fabric Compatibility II — 0.17.1

NeverLauncher 0.17.1 добавляет production-сертификацию **Fabric 1.14+ → current** поверх Minecraft Compatibility II GA. Обязательная Fabric-линия содержит 48 stable Minecraft release ID от `1.14` до `26.3` и exact Java 8/16/17/21/25. Для client-scope target CI использует официальный Fabric Meta, материализует настоящий Vanilla+Fabric client tree и Maven libraries, проверяет package integrity, фиксирует конкретный immutable Fabric Loader и запускает materialized Fabric profile через NeverRuntime на exact Java. `1.21.1` сохраняет полный integration E2E.

Release certification fail-closed требует всю Fabric-линейку: пропуск или дубль версии, wrong Java/scope/platform, mutable `latest-stable` в фактическом result, неполное evidence или незапущенный реальный Fabric client блокируют release. Minecraft Compatibility II GA 0.17.0, JRE attestation, Compatibility Hardening 0.16.11, Actual Client E2E II и остальные loader-family gates сохраняются без ослабления.

## Compatibility Hardening — 0.16.11

NeverLauncher 0.16.11 усиливает рабочий compatibility path на отказах cache/upstream и на локальных trust boundaries. Vanilla artifacts теперь продолжают прерванные загрузки через HTTP Range только при корректном `206 Content-Range`, после чего по-прежнему обязаны совпасть с Mojang SHA-1/size; повреждённый готовый cache переносится в ограниченный quarantine. Exact-version `version.json` сохраняется как проверенный snapshot и может использоваться при недоступности Mojang upstream, но `latest`/snapshot aliases никогда не восстанавливаются из потенциально stale cache. Native extraction ограничена по количеству/размеру entries и публикуется через transactional directory replacement; legacy virtual assets/resources также строятся в staging и заменяются только после полной проверки.

Managed Java cache 0.16.11 привязан не только к vendor archive SHA-256, но и к SHA-256 фактического `bin/java`/`java.exe`; повреждённые runtime archives quarantined, полностью скачанный verified `.nlpart` может быть восстановлен без повторной сети, а Adoptium/Managed JRE requests используют bounded retry с запретом HTTPS downgrade. Existing Actual Client E2E II, cross-platform Vanilla и exact Java 8/16/17/21/25 gates сохраняются.

## Actual Client E2E II — 0.16.10

NeverLauncher 0.16.10 добавляет обязательный matching-server E2E поверх actual-client certification. Пять representative Vanilla targets — `1.7.10`/Java 8, `1.17.1`/Java 16, `1.20.4`/Java 17, `1.21.10`/Java 21 и `26.3`/Java 25 — материализуют официальный Mojang `server.jar` из той же verified `version.json`, проверяют SHA-1/size, запускают сервер на exact Java и подключают реальный клиент той же Minecraft version. PASS требует доказанный world join по server log; обычный client timeout больше не удовлетворяет этим targets.

Cross-platform Vanilla 0.16.9 сохраняется: 26.3 продолжает сертифицироваться на Windows/Linux/macOS x64/ARM64, natives изолированы по `natives/<os>/<arch>`, а platform evidence привязан к фактическому host runner.

[![Основной CI](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/ci.yml)
[![Матрица совместимости](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/compatibility.yml)
[![Device Trust Matrix](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/device-trust.yml/badge.svg?branch=main)](https://github.com/DeepLayerTeam/NeverLauncher/actions/workflows/device-trust.yml)

NeverLauncher — self-hosted LauncherOps-платформа для Minecraft-проектов. Текущий релиз — **Module Guard / 0.18.3**. Release certification связывает широкую Vanilla-базу, Java 8/16/17/21/25, cross-platform targets, matching-server joins и concrete JRE binary attestation одним fail-closed evidence boundary.

## Java 25 Vanilla — 0.16.8

`0.16.8` добавляет исполняемую exact-Java-25 policy для release-линии 26.1.x и 26.3. Vanilla materializer проверяет официальный `javaVersion.majorVersion=25` до скачивания client/assets; NeverRuntime повторяет эту проверку перед запуском. Обязательные actual-client targets — `26.1`, `26.1.1`, `26.1.2`, `26.3`, каждый через verified Mojang materialization, package verification, Managed Java 25 и реальный Minecraft client launch под Xvfb. Release certification fail-closed требует весь набор и policy `vanilla-26.1.x-26.3-java25-exact`.

## Java 21 Vanilla — 0.16.7

`0.16.7` добавляет обязательную release-line certification для `1.20.5`, `1.20.6`, `1.21`, `1.21.1`, `1.21.2`, `1.21.3`, `1.21.4`, `1.21.5`, `1.21.6`, `1.21.7`, `1.21.8`, `1.21.9`, `1.21.10`. Vanilla materializer и NeverRuntime независимо требуют `javaVersion.majorVersion=21`; missing/mismatched metadata блокируется до запуска, а release certification требует весь набор actual-client evidence. `1.21.1` сохраняет полный integration E2E, остальные targets используют реальный client launch под Xvfb.

## Java 16/17 Vanilla — 0.16.6

`0.16.6` добавляет обязательные actual-client targets `1.17.1`, `1.18.2`, `1.19.4`, `1.20.1`, `1.20.2`, `1.20.4`. Vanilla materializer и NeverRuntime независимо требуют официальный Java transition: Java 16 только для 1.17.1 в сертифицируемом диапазоне, Java 17 для 1.18.x–1.20.4. Missing/mismatched `javaVersion.majorVersion` блокируется до запуска; release certification требует весь набор и actual-client evidence.

Maintenance `0.17.0v2` дополняет эту линию версиями `1.17`, `1.18`, `1.18.1`, `1.19`, `1.19.1`, `1.19.2`, `1.19.3`, `1.20`, `1.20.3` с тем же fail-closed exact-Java enforcement. Maintenance `0.17.0v3` закрывает следующие два release gap: `1.21.11` на Java 21 и `26.2` на Java 25, включая client materialization, server install и NeverRuntime exact-major validation.

## Managed Java II — 0.16.5

`neverruntime java ensure --major <8|16|17|21|25>` выполняет полный runtime lifecycle: ищет проверенный cache, разрешает Temurin через Adoptium current GA и historical feature-release GA fallback, скачивает только по HTTPS, сверяет vendor SHA-256/size, безопасно распаковывает archive, запускает фактический `java -version` для exact major и атомарно публикует runtime в Managed Java cache. Для Java 16 historical resolver является рабочей частью install path, а не compatibility declaration.

Официальный release по-прежнему включает six-platform Temurin 21 distribution как bootstrap. Остальные majors разрешаются on-demand по реальной доступности vendor binary для текущих OS/architecture. CI 0.16.5 устанавливает Java 8/16/17/21/25 настоящим NeverRuntime, повторно читает каждую из cache и сохраняет `MANAGED_JAVA_II_EVIDENCE.json`; без этого evidence release certification не проходит.

## Legacy Vanilla — 0.16.4

`0.16.4` добавляет рабочую pre-1.7 линию `1.0` (`1.0.0` принимается CLI как alias), `1.1`, `1.2.5`, `1.3.2`, `1.4.7`, `1.5.2`, `1.6.4`, `1.7.10` на exact Java 8. Materializer строит проверяемые `pre-1.6`/`legacy` virtual assets в `assets/virtual/<asset-index>` и очищает stale generated files, а NeverRuntime формирует legacy session id для `${auth_session}` и разрешает `${game_assets}` и использует фактический virtual-assets path. Java 8 fallback теперь покрывает весь release-диапазон 1.0–1.16.5 без `javaVersion`. Каждый target проходит verified materialization, package verify, Compatibility Engine resolution и фактический запуск Minecraft под Xvfb.

`0.16.3` release-line gate `1.7.10`–`1.16.5` сохранён: classifier-only native libraries старого LWJGL/JInput не превращаются в синтетический classpath JAR, а `${user_properties}`/`${profile_properties}` продолжают поддерживаться.

## Vanilla Compatibility Baseline II — 0.16.2

`0.16.2` ввёл многоверсионную certification model: восемь обязательных Vanilla anchors (`1.7.10`, `1.12.2`, `1.16.5`, `1.17.1`, `1.18.2`, `1.20.4`, `1.20.6`, `1.21.1`) привязаны к exact Java major. В 0.16.3 этот baseline дополнен Java 8 release-line gate 1.7.10–1.16.5, а 0.16.4 добавляет pre-1.7 release-line gate.

## CI Recovery — 0.16.1

`0.16.1` — maintenance-релиз без новой DB migration и без ослабления release/security gates. Он исправляет фактические причины красного `main`: Fabric Loom теперь может регистрировать собственный remapped-mod repository; production Compose CI получает обязательную WebAuthn-конфигурацию; Desktop frontend использует типы, соответствующие реальным ответам Backend API; NeverRuntime исправляет Rust lifetime error `E0716`; Tauri Device Trust включает требуемую `hardware-enclave` encryption feature; Windows hardening gate проверяет актуальный `signtool`/RFC3161/Authenticode pipeline. Rust jobs нормализуют исходники через `cargo fmt` перед строгими `cargo test`/`cargo clippy -D warnings`, поэтому форматирование больше не скрывает реальные compile/test failures.

Compatibility, Device Trust, NeverGuard и ServerBridge остаются fail-closed: CI Recovery не заменяет E2E декларациями и не переводит обязательные jobs в `continue-on-error`.

## Production Delivery Release — 0.16.0

`0.16.0` переводит прошедший 0.15.11 RC-контур в stable GA release. Перед финальным Ed25519 signing создаётся `PRODUCTION_DELIVERY_RELEASE.json`: он связывает exact source commit, `PRODUCTION_RELEASE_CANDIDATE.json`, `DELIVERY_MANIFEST.json`, six-target public matrix, Windows/Linux/macOS production evidence, Managed JRE, current root-signed trust policy, Compatibility/Device Trust/Guard/ServerBridge certifications, SBOM и provenance одним `boundarySha256`.

GA допускается только для чистой SemVer без `-prerelease`/`+build` suffix. Public origin обязан быть HTTPS и содержать immutable version segment `0.16.0` или `v0.16.0`; generic `/latest`/`stable` URL не проходит certification. `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` теперь публикует RC certificate для 0.15.11+ и `PRODUCTION_DELIVERY_RELEASE.json` для 0.16.0 как отдельные controls, поэтому post-publish E2E скачивает оба certification слоя вместе с release signatures и повторно проверяет полный bundle.

```bash
export NEVERLAUNCHER_SOURCE_COMMIT="$(git rev-parse HEAD)"
export NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL="https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v$(cat VERSION)"
./scripts/release/build-release.sh

nl release candidate-verify "dist/release-$(cat VERSION)"
nl release production-verify "dist/release-$(cat VERSION)"
nl release publish-check "dist/release-$(cat VERSION)" \
  --public-key /etc/neverlauncher/root-public.pem \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/release-trust-state.json
```

`RELEASE_MANIFEST.json` для 0.16.0 имеет `channel=stable`, `releaseStatus=production-delivery-release` и SHA-256 GA certificate. Любое изменение candidate/production evidence/public matrix/trust policy после promotion ломает candidate или GA boundary, а любое изменение после signing дополнительно ломает Release Verification v2 signature.

## Production release candidate — 0.15.11

`0.15.11` является строгим production RC поверх delivery-контура 0.15.1–0.15.10. Обычный structurally valid/unsigned candidate больше не подходит: release build требует один exact Git commit для Compatibility, Device Trust и Guard CI certification, production Authenticode/RFC3161 на Windows, Developer ID + Accepted notarization/stapling/Gatekeeper на macOS, six-target Managed JRE/Public Delivery Matrix и все предыдущие updater/trust gates.

Перед Ed25519 signing создаётся `PRODUCTION_RELEASE_CANDIDATE.json`. Он содержит exact `sourceCommit`, обязательные RC gates и SHA-256/size каждого top-level pre-sign release file; `cohortSha256` вычисляется по отсортированному inventory. После этого RC certificate попадает в `RELEASE_MANIFEST.json`/`SHA256SUMS` и подписывается Release Verification v2. Любая подмена либо добавление файла после certification обнаруживается fail-closed.

```bash
export NEVERLAUNCHER_SOURCE_COMMIT="$(git rev-parse HEAD)"
# build-release.sh также требует полный Compatibility/Device Trust/Guard CI evidence set
./scripts/release/build-release.sh

nl release candidate-verify "dist/release-$(cat VERSION)"
nl release publish-check "dist/release-$(cat VERSION)" \
  --public-key /etc/neverlauncher/root-public.pem \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/release-trust-state.json
```

Production build выполняется только из Git checkout без tracked/staged drift относительно `HEAD`; `NEVERLAUNCHER_SOURCE_COMMIT` обязан совпадать с этим `HEAD`. Post-publish public E2E из 0.15.9 остаётся финальной проверкой уже опубликованных GitHub Release bytes.

## Migration + stabilization — 0.15.10

`0.15.10` не добавляет DB migration: релиз стабилизирует локальный upgrade path 0.15.9 → 0.15.10. Release Verification v2 теперь сериализует весь verify→trust-state commit через внешний `<trust-state>.lock`, а state schema `2.1` дополнительно фиксирует SHA-256 уже принятого `RELEASE_MANIFEST.json`. Поэтому downgrade по версии/epoch и подмена другого bundle под уже принятую ту же версию блокируются fail-closed.

Updater автоматически переносит legacy macOS component state из `.neverlauncher/updater/component-update-state.json` в единый `.neverlauncher/component-update-state.json`. После durable rollback/commit staging/backup payload удаляются, journal остаётся для диагностики. Явная миграция и проверка доступны командами:

```bash
nl update migrate-state --root /opt/neverlauncher
nl update status --root /opt/neverlauncher
nl update stabilization-self-test

nl release verify dist/release-0.15.10 \
  --public-key /etc/neverlauncher/root-public.pem \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/release-trust-state.json
```

Если canonical и legacy component state имеют одну версию, но разные component hashes, migration останавливается и требует ручной проверки; более новый state никогда не заменяется старым. Stale trust-state lock удаляется только если PID владельца уже не существует.

## Public Production Delivery Matrix + E2E — 0.15.9

`0.15.9` добавляет `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json`, который публикует фактический six-target inventory для Windows/Linux/macOS x64+ARM64. Каждый target содержит exact CLI, Desktop, NeverGuard, NeverRuntime, production package и Managed JRE; Linux дополнительно содержит Backend API. URL, SHA-256 и size берутся из реального `DELIVERY_MANIFEST.json`, а сама matrix входит в signed release boundary через `RELEASE_MANIFEST.json`/`SHA256SUMS`.

После публикации GitHub Release workflow `public-production-delivery.yml` запускает настоящий network E2E: скачивает matrix и все публичные assets по HTTPS, повторно проверяет hash/size, скачивает release controls и выполняет Release Verification v2 с внешними offline-root/current trust policy/trust state.

```bash
VERSION="$(cat VERSION)"
nl delivery verify-public-matrix --bundle "dist/release-${VERSION}" --version "${VERSION}"
nl delivery public-e2e \
  --matrix-url "https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v${VERSION}/PUBLIC_PRODUCTION_DELIVERY_MATRIX.json" \
  --public-key /etc/neverlauncher/root-public.pem \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/public-e2e-trust-state.json \
  --report PUBLIC_DELIVERY_E2E_REPORT.json
```

## Проверка релиза v2 и lifecycle доверия/ключей — 0.15.8

`0.15.8` отделяет offline root trust anchor от online release-signing keys. `security rotate-key` создаёт новый release key и переводит предыдущий active key в `verify-only`; `security revocation-list --revoke <id>` блокирует скомпрометированный key. `security trust-policy` экспортирует root-signed `RELEASE_TRUST_POLICY.json`, а release verification сохраняет persistent state с максимальными trust epoch и принятой release version.

```bash
nl security rotate-key --registry-dir /secure/neverlauncher-trust --key release-signing \
  --private-key-out /secure/release-private.pem --public-key-out /secure/release-public.pem
nl security trust-policy --registry-dir /secure/neverlauncher-trust \
  --root-private-key /offline/root-private.pem --policy-out /secure/RELEASE_TRUST_POLICY.json
nl security trust-verify --path /secure/RELEASE_TRUST_POLICY.json \
  --root-public-key /etc/neverlauncher/root-public.pem

nl release build --out "dist/release-${VERSION}" --trust-policy /secure/RELEASE_TRUST_POLICY.json
nl release sign "dist/release-${VERSION}" --private-key /secure/release-private.pem
nl release verify "dist/release-${VERSION}" --public-key /etc/neverlauncher/root-public.pem \
  --trust-state /var/lib/neverlauncher/release-trust-state.json \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json
```

`trust-state` должен храниться вне release bundle. После принятия более нового trust epoch или release version проверка старого bundle блокируется как rollback.

## Транзакционное обновление Desktop/Guard/Runtime — 0.15.7

`0.15.7` использует 0.15.6 transaction engine для self-update самого NeverLauncher. Desktop принимает production package и pinned SHA-256, останавливает NeverGuard и запускает соседний CLI helper с `update components`; helper ждёт завершения Desktop и только после этого изменяет live installation. Desktop, NeverGuard и NeverRuntime проверяются и переключаются одной транзакцией, поэтому ошибка одного компонента откатывает весь набор.

Windows и Linux используют adjacent-file update с durable journal/backup/post-verify. Windows дополнительно повторно проверяет Authenticode и timestamp identity каждого PE; Linux сверяет ELF architecture и SHA-256. На macOS частичная замена внутренних Mach-O запрещена: staging содержит целый notarized `NeverLauncher.app`, updater atomically меняет app directory, затем повторно выполняет `codesign --verify`, `stapler validate` и Gatekeeper assessment; при любой ошибке старый app bundle восстанавливается.

```bash
nl update components --package ./neverlauncher-desktop-0.15.7-linux-x64.tar.gz --expected-sha256 <sha256> --current-desktop ./neverlauncher-desktop --wait-pid <pid> --restart
nl update component-self-test
```

## Unified Transactional Updater Core — 0.15.6

`0.15.6` заменяет последовательную замену client-файлов единым transactional updater engine. Перед изменением live tree все новые bytes копируются в staging внутри того же install root, проверяются по SHA-256/size, а затрагиваемые текущие файлы сохраняются в transaction backup. Только после durable `prepared` journal начинается switch; каждая замена выполняется через same-filesystem atomic rename/replace, а удаление obsolete-файлов входит в ту же transaction boundary.

Journal хранится в `.neverlauncher/updater/transactions/<id>/journal.json` и проходит состояния `staging → prepared → committing → verifying → committed`. Ошибка source hash, atomic switch или post-verify запускает обратное восстановление всех touched paths; незавершённые `prepared/committing/verifying` transaction автоматически восстанавливаются перед следующим update или явно через `nl update recover --root <dir>`. Lock содержит PID и умеет освобождать stale lock после crash; destination/source symlink и path traversal отклоняются fail-closed.

Рабочий core используется `nl client install`, `nl client update`, `nl client repair`, `nl client rollback` и `nl client package-apply/package-consume`; `client-state.json` записывается внутри той же транзакции. Generic manifest path доступен через `nl update apply --from old.json --to new.json --source-root <dir> --root <install>`, а `nl update status` показывает durable journals. `nl update self-test` реально выполняет commit + obsolete removal + forced verification failure + rollback; CI запускает этот self-test на native Linux x64/ARM64, Windows и macOS runners, а `release publish-check` для `0.15.6+` выполняет его повторно.

```bash
nl update apply --from old.json --to new.json --source-root ./payload --root ./install
nl update status --root ./install
nl update recover --root ./install
nl update self-test
```

## Managed JRE Distribution — 0.15.5

`0.15.5` переносит Java 21 runtime из best-effort download в production delivery boundary. `scripts/release/managed-jre-distribution.py` получает шесть точных Eclipse Temurin JRE archive: Windows/Linux/macOS × x64/ARM64, проверяет upstream SHA-256/size и фактическую архитектуру `bin/java`, не перепаковывает vendor bytes и создаёт `MANAGED_JRE_MANIFEST.json` + `MANAGED_JRE_EVIDENCE.json`.

`nl delivery verify-jre` и `nl release publish-check` fail-closed проверяют все шесть target, exact vendor checksums, archive format/content и binding к `DELIVERY_MANIFEST.json`. `NeverRuntime` умеет использовать локальный или HTTPS distribution manifest; для HTTPS обязателен SHA-256 pin manifest. Установка выполняется через hash-addressed download cache, `java -version` verification и atomic runtime directory replacement. Прямой Adoptium API остаётся fallback только когда managed distribution явно не настроена.

```bash
python3 scripts/release/managed-jre-distribution.py --out dist/managed-jre-0.15.5 --version 0.15.5 --major 21
nl delivery manifest --bundle dist/managed-jre-0.15.5 --version 0.15.5
nl delivery verify-jre --bundle dist/managed-jre-0.15.5 --version 0.15.5
neverruntime java ensure --major 21 --distribution temurin --manifest ./MANAGED_JRE_MANIFEST.json
```

Для release staging задаётся `NEVERLAUNCHER_MANAGED_JRE_ARTIFACTS_DIR`; remote runtime distribution задаётся `NEVERLAUNCHER_MANAGED_JRE_MANIFEST` вместе с `NEVERLAUNCHER_MANAGED_JRE_MANIFEST_SHA256`.

## Notarized macOS x64 + ARM64 — 0.15.4

`0.15.4` переводит macOS delivery с legacy `macos-universal` Guard certification на два канонических thin Mach-O target: `macos-x64` и `macos-arm64`. `scripts/release/build-macos-production.sh` собирает CLI, Desktop, NeverGuard и NeverRuntime отдельно для `x86_64-apple-darwin` и `aarch64-apple-darwin`, проверяет фактический Mach-O `cputype`, подписывает вложенные binaries и `.app` через Developer ID Application с Hardened Runtime и timestamp.

Production pipeline отправляет каждую architecture-specific `.app` в Apple notary service через `xcrun notarytool submit --wait`, требует `Accepted`, затем выполняет `stapler staple`, `stapler validate`, `spctl --assess` и `codesign --verify --deep --strict`. После stapling создаются финальные `neverlauncher-desktop-0.15.4-macos-{x64,arm64}.zip`; `MACOS_NOTARIZATION_EVIDENCE.json`, per-arch package manifests и `GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json` связывают exact bytes с `DELIVERY_MANIFEST.json`.

`nl delivery verify-macos --production` и `nl release publish-check` fail-closed требуют обе архитектуры, `LC_CODE_SIGNATURE`, Developer ID Team ID, Hardened Runtime, Accepted notarization, stapled ticket и Gatekeeper evidence. Обычный CI может создавать только `adhoc-development` candidate для regression tests; он не проходит production publish-check. Legacy `macos-universal` остаётся только Guard CI certification input и исключается из publishable delivery для `0.15.4+`.

## Linux x64 + ARM64 production packages — 0.15.3

`0.15.3` убирает `linux-amd64` из publishable delivery и вводит канонические `linux-x64`/`linux-arm64` артефакты для CLI, Backend API, Desktop, NeverGuard и NeverRuntime. `scripts/release/build-linux-production.sh` запускается на нативном runner соответствующей архитектуры, а `scripts/release/linux-package.py` проверяет ELF64 `e_machine` (`EM_X86_64`/`EM_AARCH64`) и создаёт детерминированный `neverlauncher-linux-<arch>-<version>.tar.gz` со встроенным `LINUX_PACKAGE_MANIFEST.json`.

`LINUX_PRODUCTION_EVIDENCE.json` и `GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json` агрегируют обе архитектуры. `nl delivery verify-linux` и `nl release publish-check` повторно проверяют ELF architecture, SHA-256/size, executable modes, содержимое tar.gz, embedded manifest и привязку каждого файла к `DELIVERY_MANIFEST.json`. Исторический `linux-amd64` остаётся только в Guard CI certification и исключается из publishable delivery inventory для `0.15.3+`.

Main CI использует отдельные native jobs на `ubuntu-24.04` и `ubuntu-24.04-arm`; aggregate release принимает их exact outputs через `NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR`, не пересобирая ARM64 на x64 runner.

## Signed Windows x64 + ARM64 — 0.15.2

`0.15.2` переводит Windows delivery из single-architecture candidate в dual-architecture production boundary. `scripts/release/build-windows-desktop.ps1` собирает отдельные `x86_64-pc-windows-msvc` и `aarch64-pc-windows-msvc` Desktop/NeverGuard binaries и отдельные Go CLI `amd64`/`arm64`, проверяет PE Machine до и после подписи и выпускает канонические `windows-x64`/`windows-arm64` artifacts.

Production-подпись выполняется Windows SDK `signtool`: SHA-256 file digest, RFC3161 `/tr` timestamp и SHA-256 timestamp digest. После каждого sign выполняются `signtool verify /pa /all` и `Get-AuthenticodeSignature`; отсутствие валидной подписи, timestamp certificate, требуемой архитектуры или совпадающего signer thumbprint блокирует сборку. PFX можно передать только извне через secret/file; импортированный сертификат удаляется из `CurrentUser\My` в `finally`.

`WINDOWS_SIGNING_EVIDENCE.json` связывает signer, timestamp server, x64/ARM64 PE metadata, реальные hashes/sizes и package manifests с `DELIVERY_MANIFEST.json`. `nl delivery verify-windows --production` и `nl release publish-check` для `0.15.2+` fail-closed требуют обе архитектуры и проверяют package ZIP, embedded manifest, signed Desktop/NeverGuard bytes и `GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json`. Обычный CI может создать только `unsigned-development` candidate для тестов, но такой bundle не проходит production publish-check.

Отдельный workflow `.github/workflows/windows-production-delivery.yml` предназначен для реальной signing job на Windows runner с `WINDOWS_CODESIGN_PFX_BASE64`/`WINDOWS_CODESIGN_PFX_PASSWORD`. Aggregate release принимает результат через `NEVERLAUNCHER_WINDOWS_SIGNED_ARTIFACTS_DIR`; исторические `windows-amd64` aliases остаются только для Guard CI compatibility и не попадают в delivery manifest 0.15.2.

## Production Delivery — 0.15.1

`0.15.1` вводит первый рабочий слой Production Delivery. `nl release build` формирует `DELIVERY_MANIFEST.json` по реальным байтам release bundle, нормализует OS/CPU (`windows|linux|macos`, `x64|arm64|universal`) и помещает manifest в общий signed checksum boundary. `nl release verify` заново проверяет каждый перечисленный artifact, поэтому ручная правка manifest, замена файла после сборки или path traversal блокируют публикацию.

Для диагностики и интеграции доступны `nl delivery target`, `nl delivery verify` и `nl delivery resolve`. Resolver принимает aliases вроде `amd64`/`x86_64` и `aarch64`; macOS universal artifact совместим с обеими native архитектурами. Manifest не заявляет отсутствующие ARM64/x64 сборки: `publishedTargets` выводится только из фактически находящихся в bundle platform artifacts.

## ServerBridge 2 Release — 0.15.0

`0.15.0` закрепляет ServerBridge 2 как production release без новой DB migration поверх `0030`. `scripts/build/bridge-plugins.sh` обязан собрать все 11 platform-matched JAR и завершиться `SERVERBRIDGE2_CERTIFICATION.json`; certification сверяет public matrix, manifest, фактические JAR, SHA256SUMS и exact-version `BRIDGE_RELEASE_ALLOWLIST.json`. Production release bundle и `nl release publish-check` fail-closed требуют эту certification и повторно хэшируют каждый bridge artifact.

Главное изменение Minecraft Compatibility Release относительно `0.10.7` — compatibility evidence теперь связано с самим production release: официальный `release publish-check` требует machine-verifiable матрицу для той же версии/commit, проверяет все required targets и включает matrix/targets/certification в общий `SHA256SUMS`, Ed25519 signature и provenance boundary. Bundle без такого evidence можно собрать как CI candidate, но нельзя подтвердить как Minecraft Compatibility Release.

## Forge + NeoForge Server Bridge — 0.14.7

Forge и NeoForge 1.21.1 работают как независимые `kind=forge` и `kind=neoforge` ServerBridge nodes. Оба мода используют штатный pre-world `PlayerNegotiationEvent` как async login gate, общий bounded network runtime и локальную Ed25519 identity. Release `0.14.7+` требует отдельные `forgeSha256` и `neoforgeSha256`; artifacts и identities платформ не взаимозаменяемы.

## Fabric Server Bridge — 0.14.6

Fabric 1.21.1 работает как отдельный `kind=fabric` ServerBridge node. Мод подключается только на сервере, использует Fabric API login synchronizer для fail-closed асинхронной проверки login, хранит private Ed25519 key локально и передаёт Backend только signed Protocol v2 requests. Release `0.14.6+` требует отдельный `fabricSha256`; Fabric JAR не взаимозаменяем с Bukkit/proxy artifacts.

## ServerBridge 0.14.5 Proxy family

Velocity, BungeeCord и Waterfall используют общий production proxy runtime с Ed25519 node identity, signed Protocol v2 requests, artifact SHA-256 enforcement и one-time join tickets. Для BungeeCord/Waterfall выпускаются отдельные JAR; platform mismatch fail-closed. Production release 0.14.5 требует hashes всех proxy и Bukkit-family artifacts.


## Bukkit family — 0.14.4

`0.14.4` переводит Bukkit-совместимые ServerBridge-плагины на один production runtime `bukkit-family-common` и пять platform-matched artifacts: Bukkit/CraftBukkit, Spigot, Paper, Purpur и Folia. Общий runtime выполняет Ed25519 node authentication, SHA-256 self-measurement, heartbeat, one-time join validation, fail-closed login enforcement и diagnostics; платформенные JAR содержат только явный runtime discriminator и descriptor. JAR от другой платформы не запускается молча: mismatch приводит к отключению plugin.

Folia не использует Bukkit scheduler для backend I/O: heartbeat/reload выполняются собственным bounded daemon executor, а async pre-login остаётся сетевой границей авторизации. Release policy `0.14.4+` требует отдельный SHA-256 allowlist для `velocity`, `bukkit`, `spigot`, `paper`, `purpur` и `folia`. Migration `0024_bukkit_family_0144` расширяет PostgreSQL kind constraint без изменения существующих node identities/tickets; production E2E запускает реальные Spigot/Paper/Purpur/Folia server artifacts и проверяет allow → replay deny → revoke → deny.

## Cryptographic Node Identities — 0.14.2

`0.14.2` заменяет ServerBridge shared bearer credentials на Ed25519 node identity. Приватный ключ создаётся и хранится локально bridge-плагином в `node-identity.properties`; Backend получает только raw public key/fingerprint и `identityEpoch`. Каждый privileged request подписывает canonical method/path/body hash вместе с Unix timestamp и 192-bit nonce. PostgreSQL атомарно consume-ит nonce, поэтому повтор корректно подписанного запроса отклоняется.

Migration `0022_serverbridge_crypto_node_identities_0142` удаляет legacy token hashes, переводит существующие 0.14.1 nodes в `identity-enrollment-required` и инвалидирует активные join tickets. Для upgrade установите bridge 0.14.2, получите его `publicKey`/fingerprint из startup log и административно вызовите `/api/v1/server-bridge/servers/{serverId}/rotate-identity`; после этого node получает новый `identityEpoch` и становится `active`. Protocol v2, PostgreSQL source of truth и atomic one-time join semantics из 0.14.1 сохраняются.

## NeverGuard Release — 0.14.0

`0.14.0` переводит NeverGuard из набора platform implementations в единый production release boundary. Windows, Linux и macOS продолжают использовать authenticated IPC v4; после handshake Desktop обязательно получает authenticated `status` от реально запущенного Guard и сверяет `productVersion`, platform identity и protocol version до дальнейших команд.

Backend для `0.14+` принимает только `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON` schema 2.0. Policy хранит **точные пары** SHA-256 Desktop+NeverGuard отдельно для `windows`, `linux`, `macos`, поэтому hash одного разрешённого Guard больше нельзя комбинировать с Desktop из другой разрешённой сборки. Release identity (`schema/protocol/platform`) также сохраняется в one-time challenge/ticket binding и повторно учитывается live Minecraft/ServerBridge integrity policy.

Каждый platform builder создаёт собственный v2 fragment. После финальной vendor signing используйте `scripts/release/merge-guard-release-policy.py --windows ... --linux ... --macos ... --output GUARD_RELEASE_POLICY.json`: production merger требует Authenticode Windows, Developer ID + notarization macOS и полный набор трёх платформ. Полученный JSON целиком задаётся в `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`.

## Сертификация Cross-platform Guard release — 0.13.9

`0.13.9` вводит единый certification boundary поверх production NeverGuard реализаций Windows, Linux и macOS. Каждый platform CI job обязан завершить native Guard tests, integration test, clippy/release build, platform production gate и package verification, после чего создаёт `guard-ci-result.json` для exact commit/run с SHA-256 package, Desktop, Guard, package manifest и release allowlist. Aggregate job принимает релиз только при PASS всех трёх обязательных targets.

Финальный release не пересобирает сертифицированные platform artifacts: `scripts/guard_ci/stage_release.py` переносит именно outputs прошедшего CI и повторно сверяет их хэши. Для `0.13.9+` `nl release publish-check` требует `GUARD_CI_TARGETS.json`, `GUARD_CI_MATRIX.json`, `GUARD_CI_CERTIFICATION.json` и заново хэширует каждый сертифицированный Windows/Linux/macOS artifact уже внутри подписанного bundle. CI evidence не заменяет production Authenticode/Developer ID/notarization и явно не утверждает владение vendor signing credentials.

## NeverGuard macOS production — 0.13.8

macOS использует отдельный native NeverGuard boundary: authenticated Unix-domain socket protocol v4, kernel peer PID/UID validation, `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, parent-exit kqueue watch и отдельную Minecraft process group. Integrity Evidence/Guard Attestation имеют собственные macOS schemas и включают SHA-256 Mach-O, process boundary, code signature, Hardened Runtime и library validation; Backend проверяет их независимо от Windows/Linux policy.

Production package строится `scripts/release/build-macos-desktop.sh`: universal `arm64 + x86_64` `.app`, Developer ID Application signing, Hardened Runtime, notarization/stapling и Gatekeeper assessment. Перед spawn Guard Desktop fail-closed проверяет `MACOS_PACKAGE_MANIFEST.json`, expected signing identifiers/Team ID, подписи и notarization status. `--allow-ad-hoc` предназначен только для CI/development artifact и не является production-runnable package.

## Рабочий контур

```text
Mojang metadata -> проверенное Vanilla tree
Forge/NeoForge Maven -> installer.jar + SHA-1
                     -> install_profile.json/version.json
                     -> embedded Maven + verified dependencies
                     -> client processors + output verification
                     -> normalized child version profile
                     -> SHA-256 Never package -> signed immutable release
                     -> Compatibility Engine -> Managed Java -> JVM
```

Сохраняется processor-based Forge/NeoForge pipeline, введённый в `0.10.4`, и стабилизационный hardening `0.10.7`: exclusive materialization lock, bounded upstream retry, symlink-safe client tree, deterministic natives/processors state и строгий CI evidence.

## Minecraft Compatibility Release

NeverLauncher **0.18.0 Loader Compatibility GA** fail-closed ограничивает production materializers точным сертифицированным support surface: Fabric/Quilt 1.14–26.3 по зафиксированным release IDs, Forge modern 1.13.2–26.3 по сертифицированным IDs плюс реальные legacy 1.7.10/1.12.2, NeoForge 1.20.1–26.2. Для каждой комбинации проверяется exact Java major; версии вне GA surface не запускают loader install.

- exclusive materialization lock на каждый `clientDir` для Vanilla/Fabric/Quilt/Forge/NeoForge;
- retry transient HTTP `408/425/429/5xx` и bounded `Retry-After`;
- запрет symlink-компонентов внутри materialized client tree и symlink artifacts при package build;
- portable atomic replacement повреждённых файлов;
- очистка и полная пересборка generated natives перед упаковкой;
- очистка Forge/NeoForge installer scratch data перед processors;
- Compatibility Engine повторно проверяет отсутствие symlink path components непосредственно перед runtime resolution;
- CI aggregator требует `exitCode=0`, healthy Paper, полный evidence set и loader identity, а не только поле `status=passed`.

Эти проверки находятся в исполняемом коде и regression tests; repository policy дополнительно запрещает выпуск при удалении обязательных compatibility primitives.

### Release-bound compatibility certification

Официальный publish flow использует агрегированный `matrix.json` из `.github/workflows/compatibility.yml`. Для 0.18.0 GA release bundle содержит четыре обязательных compatibility-файла:

```text
COMPATIBILITY_TARGETS.json
COMPATIBILITY_MATRIX.json
COMPATIBILITY_CERTIFICATION.json
LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json
```

Базовый certification повторно проверяет product version, exact source commit, run ID, полный набор required targets, immutable resolved loader versions, `exitCode=0`, actual-client/package/signature/sync/Paper/revoke evidence и SHA-256 каждого per-target evidence JSON. Loader Compatibility GA строит единый SHA-256 evidence root всех 292 targets, фиксирует family/platform/Java/scopes и обязательные pinning/native-E2E/cross-platform/hardening invariants. Дополнительно сертификат связывает SHA-256 исполняемого GA support policy (163 loader/Minecraft линии, включая Forge legacy 1.7.10/1.12.2). `RELEASE_MANIFEST.json` требует `loaderCompatibilityGA=true` и совпадающий support SHA; все четыре файла входят в `SHA256SUMS` и защищены общей Ed25519 release signature.

Сборка сертифицированного bundle:

```bash
export NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE=/path/to/matrix.json
export NEVERLAUNCHER_SOURCE_COMMIT=$(git rev-parse HEAD)
bash scripts/release/build-release.sh
```

Финальная проверка перед публикацией:

```bash
VERSION="$(cat VERSION)"
nl release publish-check "dist/release-${VERSION}" --public-key /secure/release-public.pem
```

## Managed Java

NeverRuntime выбирает JVM требуемой major-версии и при необходимости устанавливает проверенный Temurin runtime. Для Java 21 в production используется Managed JRE Distribution 0.15.5; локальный/HTTPS manifest выбирает platform/architecture artifact и проверяется до установки. Поддерживаются Java 8, 17, 21 и 25; без настроенного distribution manifest сохраняется совместимый direct-Adoptium fallback. Forge/NeoForge processor pipeline принимает `--java` или `NEVERLAUNCHER_JAVA`; если путь не задан, используется подходящая системная Java. Версия JVM проверяется до запуска processors.

```bash
neverruntime java ensure --major 21 --distribution temurin
```

## Vanilla / Fabric / Quilt

Сохраняется materialization-контур `0.10.2`–`0.10.3`: Mojang client/libraries/assets/natives/logging проверяются по upstream SHA-1/size и затем фиксируются SHA-256 в Never release; Fabric и Quilt получают concrete loader profile через официальные Meta API и materialize Maven dependencies до публикации immutable release.

```bash
nl runtime vanilla-package --minecraft 1.21.1 --client-dir .neverlauncher/vanilla/1.21.1 --output client-package.json
nl runtime fabric-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/fabric/1.21.1 --output client-package.json
nl runtime quilt-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/quilt/1.21.1 --output client-package.json
```

## Forge + NeoForge

Новые materializer-команды:

```bash
nl runtime forge-install \
  --minecraft 1.20.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/forge/1.20.1

nl runtime forge-package \
  --minecraft 1.20.1 \
  --loader-version 47.4.0 \
  --client-dir .neverlauncher/forge/1.20.1 \
  --project my-project \
  --profile forge \
  --channel stable \
  --output client-package.json

nl runtime neoforge-package \
  --minecraft 1.21.1 \
  --loader-version latest-stable \
  --client-dir .neverlauncher/neoforge/1.21.1 \
  --project my-project \
  --profile neoforge \
  --channel stable \
  --output client-package.json
```

Production pipeline выполняет:

1. разрешение Minecraft и materialization Vanilla base;
2. выбор конкретной Forge/NeoForge версии через Maven metadata либо явный `--loader-version`;
3. загрузку официального `installer.jar` только по HTTPS и проверку upstream `.sha1`;
4. чтение `install_profile.json` и встроенного `version.json` непосредственно из installer JAR;
5. безопасное извлечение встроенного `maven/` и installer `data/` без path traversal/symlink;
6. materialization installer libraries и processor classpath;
7. выполнение только client processors через Java, с `Main-Class` из JAR manifest, timeout и прямой передачей аргументов без shell;
8. разрешение Forge/NeoForge installer tokens `{ROOT}`, `{MINECRAFT_JAR}`, `{INSTALLER}`, `{LIBRARY_DIR}`, `{SIDE}`, `{DATA}` и Maven references `[group:artifact:version...]`;
9. проверку processor outputs по SHA-1/SHA-256 и пропуск уже корректно созданных outputs при повторной установке;
10. materialization runtime libraries из child `version.json`, включая локально сгенерированные processor artifacts;
11. запись нормализованного `versions/<id>/<id>.json` и стандартную упаковку в SHA-256 Never package.

Для тестов/зеркал доступны `--installer-url`, `--installer-sha1` и `--maven-metadata-url`. В strict mode отсутствие корректного checksum завершает materialization ошибкой.

Текущий compatibility release поддерживает processor-based Forge installers поколения 1.13+ и NeoForge installer format. Legacy Forge до 1.13 намеренно не объявляется готовым и остаётся отдельной задачей compatibility hardening.

## Compatibility Engine

При `runtime.launch.classpathStrategy = "compatibility"` NeverRuntime читает подписанный child `version.json`, разрешает `inheritsFrom`, Mojang rules, ordered classpath, native classifiers, JVM/game arguments и logging config. Forge/NeoForge child profile поэтому запускается тем же runtime path, что Vanilla/Fabric/Quilt, без отдельного launch fallback.

Каждый metadata/classpath/native/logging path, использованный engine, обязан входить в подписанный manifest. Installer JAR и промежуточные installer data хранятся в `.neverlauncher/` и в клиентский package не попадают; только нормализованные runtime artifacts становятся частью immutable release.

Прямое разрешение установленного дерева:

```bash
neverruntime compatibility --root .neverlauncher/client --version <profile-id>
```

## Компоненты

- **Backend API** — единый `/api/v1`, миграции PostgreSQL, подписанные манифесты, авторизация и серверные сессии, Redis rate limiting, доверенные proxy, local/S3-хранилище, резервное копирование, диагностика и ServerBridge.
- **CLI `nl`** — рабочие сценарии установки, авторизации, администрирования, операций, пакетов, релизов и runtime через `/api/v1`; исторические status-only семейства команд удалены.
- **NeverRuntime** — Rust runtime/CLI для Ed25519-проверки, потоковой загрузки и SHA-256, восстановления клиента, определения Java, построения плана запуска и запуска процесса.
- **Desktop** — Tauri-адаптер поверх NeverRuntime с системным защищённым хранилищем учётных данных и контролируемыми JVM-процессами.
- **Admin** — Vite-приложение в неизменяемом production-образе Nginx с CSP.
- **ServerBridge** — реальные плагины Velocity и Bukkit-family (Bukkit/Spigot/Paper/Purpur/Folia), собираемые против платформенного API и общего security runtime.
- **Развёртывание** — PostgreSQL, Redis с паролем, Backend, Admin и Nginx с fail-closed rate limiting и явным списком доверенных proxy CIDR.

## Канонический API

В production регистрируется только `/api/v1`. Исторические маршрутизаторы `/api/v2`–`/api/v5` отсутствуют намеренно. Канонический контракт хранится в:

```text
schemas/openapi.yaml
```

Перегенерация и проверка контракта по фактическому Go-router:

```bash
python3 scripts/contracts/generate_openapi.py
python3 scripts/contracts/validate-openapi.py
```

Проверка завершается ошибкой, если набор операций router и OpenAPI расходится.

## Локальная проверка

```bash
./scripts/release/preflight.sh
```

Локальный preflight выполняет доступный контур и явно не объявляет его production-ready при пропусках. Для релиза используйте строгий режим, который требует все обязательные проверки:

```bash
NEVERLAUNCHER_PREFLIGHT_STRICT=1 ./scripts/release/preflight.sh
```

Для диагностического локального прогона frontend и Tauri можно включить отдельно:

```bash
NEVERLAUNCHER_PREFLIGHT_FRONTEND=1 ./scripts/release/preflight.sh
NEVERLAUNCHER_PREFLIGHT_TAURI=1 ./scripts/release/preflight.sh
```

## Публичная CI Compatibility Matrix

Канонические цели хранятся в `compatibility/targets.json`; в них нет ручных PASS/FAIL. Workflow `.github/workflows/compatibility.yml` строит dynamic matrix и запускает настоящий клиент для каждого target. Текущая обязательная матрица содержит 292 targets: 109 Vanilla, 53 Fabric, 53 Quilt, 50 Forge и 27 NeoForge. Исторические широкие loader-линии остаются Linux x86_64 regression-базой, а current-loader anchors дополнительно сертифицируются на Windows/Linux/macOS × x64/ARM64; `1.21.1` сохраняет loader-native integration E2E. Mutable loader selector `latest-stable` разрешается в конкретную версию до публикации и не может попасть в PASS-результат как итоговая loader version.

Каждый case генерирует `compatibility-result.json` только после прохождения обязательных evidence-checks: локальная проверка package, Ed25519-подпись immutable manifest, clean sync, запуск настоящего клиента, вход на Paper и fail-closed deny после revoke. Агрегатор `scripts/compatibility/matrix.py` проверяет exact target, commit, Actions run ID, concrete loader version и completeness evidence; missing/duplicate/invalid result делает матрицу failed. Итоговые `matrix.json` и `matrix.md` публикуются в Actions Summary и как artifact.

Локальная проверка definition/aggregator:

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

Подробности: `compatibility/README.md`.

## Настоящий Minecraft Client E2E

Блокирующий production release gate по умолчанию проверяет Vanilla, а compatibility workflow использует тот же production-путь для всех пяти loader families. Java fixture не используется как доказательство совместимости клиента:

```text
официальный Mojang version manifest
 -> Minecraft 1.21.1 client/libraries/assets/natives/logging
 -> полный локальный SHA-256 verify
 -> upload через canonical /api/v1
 -> Ed25519 signed immutable release
 -> чистый NeverRuntime sync из Backend
 -> pinned signature + SHA-256 verify
 -> Xvfb + software OpenGL
 -> настоящий Minecraft Java Client
 -> --quickPlayMultiplayer 127.0.0.1:25571
 -> настоящий Paper 1.21.1
 -> NeverLauncher ServerBridge allow
 -> E2EPlayer joined the game
 -> revoke session -> subsequent join denied
```

Для CI добавлен безопасный `--max-runtime-seconds`: NeverRuntime сам завершает долговременно работающий game process после сбора E2E evidence и отражает это как `timedOut`, не оставляя Java-процесс после job.

Velocity/Purpur продолжают проходить быстрый protocol-level allow/revoke/deny тест, но такой probe больше не считается доказательством Minecraft Client compatibility.

Запуск в окружении с Docker, Gradle, JDK 21, Rust/Cargo, Go, PostgreSQL client, `curl`, `jq`, Python 3, Xvfb и OpenGL/X11 runtime:

```bash
bash e2e/scripts/run-minecraft-e2e.sh
```

## Auth Federation 0.12

`0.12.0` — стабильный Auth Federation release. Local/SQL/HTTP/OIDC/Microsoft проходят один Connector SDK/Federation Core и разрешаются в canonical Never user до выпуска Never session; passkeys/TOTP/recovery являются auth methods/MFA, а Minecraft session создаётся только поверх canonical Never session. Generic browser providers можно явно связать через `/api/v1/auth/providers/{providerId}/link/begin|complete` без auto-link по email.

Для production upgrade примените `nl db migrate apply`, затем `nl db migrate verify`. Migration `0011_auth_federation_release_0120` гарантирует canonical local identity для каждого password-capable user и блокирует повреждение этой связи на уровне PostgreSQL. Администратор может проверить runtime federation через `GET /api/v1/admin/auth/federation/status`; `/ready` требует хотя бы один здоровый auth provider.

## NeverGuard migration, compatibility & stabilization — 0.13.10

`0.13.10` завершает стабилизацию 0.13.x после cross-platform Guard certification. Новая PostgreSQL migration `0020_guard_migration_compatibility_stabilization_01310` проверяет persisted `minecraft_sessions` Guard snapshot и fail-closed останавливает upgrade на частичных/противоречивых security rows; после этого DB сама гарантирует atomic snapshot и freshness window, совпадающее с runtime ticket policy.

Исправлена cross-platform совместимость gameplay enforcement: macOS trusted device теперь проходит ту же обязательную live reevaluation Guard integrity в Minecraft/ServerBridge, что Windows/Linux. Guard CI target result дополнительно содержит `repository`, а aggregate/release certification отклоняет перенос PASS-evidence между fork/repository даже при совпавших commit/run strings. Для реального upgrade rehearsal используется `e2e/scripts/run-guard-migration-e2e.sh`.

## Windows production hardening — 0.13.6

`0.13.6` усиливает уже рабочий NeverGuard boundary без hooks/injection. Desktop и `neverguard.exe` до основной runtime-инициализации fail-closed включают heap termination-on-corruption и ограничивают default DLL search каталогом приложения и `System32`. NeverGuard IPC поднят до protocol v4: Named Pipe остаётся local-only, но теперь создаётся с protected current-user/System ACL; hardening version/state и наличие secure ACL входят в authenticated `ready` proof.

Desktop удерживает отдельный NeverGuard Job Object с `KILL_ON_JOB_CLOSE`, поэтому аварийное завершение launcher закрывает OS-level lifetime boundary Guard. Release build создаёт `WINDOWS_PACKAGE_MANIFEST.json` после финальной сборки, а release Desktop до spawn `neverguard.exe` требует соседний regular/non-symlink artifact и сверяет size + SHA-256 обоих executable с manifest. Для production-signing `build-windows-desktop.ps1 -CodeSigningCertificateThumbprint <thumbprint>` подписывает оба PE через Authenticode **до** вычисления hashes, повторно проверяет подписи и выставляет `authenticodeRequired/requireAuthenticode=true`; runtime затем выполняет локальный WinVerifyTrust до запуска Guard.

Unsigned development package намеренно не проходит release-runtime Authenticode gate и предназначен только для CI/build validation.

Это user-mode production hardening: он уменьшает поверхность DLL hijacking, локального IPC и orphan Guard process и делает release corruption/replacement fail-closed в штатной модели. Он не является защитой от администратора/kernel attacker и не заменяет server-side Guard Attestation/allowlist из 0.13.4–0.13.5.

## Minecraft/ServerBridge integrity enforcement — 0.13.5

`0.13.5` закрывает gameplay bypass между Guard Attestation и ServerBridge. Guard-verified metadata теперь сохраняется в самой Minecraft session и live-проверяется при validate/join/hasJoined. Для Windows Guard-enforced device Desktop передаёт новый Minecraft access token в `/api/v1/session/join`; Backend сохраняет `minecraftSessionId`, поэтому ServerBridge не может принять отдельный join, не связанный с тем credential, который получил одноразовый Guard launch ticket.

Velocity и Bukkit/Spigot/Paper/Purpur/Folia дополнительно хэшируют собственный запущенный JAR (`SHA-256`) и отправляют `pluginVersion + pluginSha256` в heartbeat и `validate-join`. Backend принимает только hashes из `NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON`, повторно проверяет текущую policy на каждом join и сбрасывает measurement после rotation node identity. `scripts/build/bridge-plugins.sh` генерирует `BRIDGE_RELEASE_ALLOWLIST.json` из фактически собранных JAR; production Backend без этой policy не проходит конфигурационную проверку.

Удаление Guard/Desktop или ServerBridge hash из соответствующего allowlist действует как live revoke: уже созданная Minecraft/ServerBridge session перестаёт проходить Backend validation. ServerBridge JAR self-hash является application-level release enforcement и не выдаётся за TPM/kernel attestation удалённого Minecraft host.

## NeverGuard: Guard Attestation и Backend verification — 0.13.4

`0.13.4` делает NeverGuard evidence серверно проверяемым в launch flow. Backend выдаёт одноразовый challenge, Desktop передаёт его в отдельный `neverguard.exe` через authenticated IPC v3, а Guard формирует свежую attestation поверх Integrity Evidence v1 и реально применённого Windows process policy. Hardware P-256 device key подписывает каноническую привязку attestation к текущим user/device/session/binding epoch и версии launcher; приватный ключ не передаётся Backend или frontend.

Backend endpoints `POST /api/v1/auth/devices/{deviceId}/guard-attest/begin|complete` проверяют одноразовость/freshness challenge, P-256 signature, evidence/attestation digests, PID boundary, process-policy flags и точные SHA-256 `neverguard.exe`/Desktop по `NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON`. После успешной проверки Backend выдаёт короткоживущий single-use Guard launch ticket. Для Windows trusted device в production `/api/v1/minecraft/session` не выдаёт игровую session без валидного ticket; повторное использование ticket отклоняется.

Windows package build создаёт `GUARD_RELEASE_ALLOWLIST.json` рядом с `WINDOWS_PACKAGE_MANIFEST.json`; его значения должны быть перенесены в production configuration после финальной сборки/подписи binaries. `requireAuthenticode` можно включить только для release pipeline, где конечные файлы действительно подписаны до вычисления allowlist hashes. Эта схема является application-level Guard Attestation, а не TPM quote/Measured Boot или kernel anti-cheat.

## NeverGuard Windows: применение runtime/process policy — 0.13.3

`0.13.3` делает Windows policy исполняемой, а не декларативной. `neverguard.exe` до запуска Tokio применяет и заново проверяет process mitigations (`DynamicCode`, `ExtensionPointDisable`, `StrictHandleCheck`, `ImageLoad`, `ChildProcess`). Applied state возвращается только по authenticated IPC `process-policy`; handshake protocol v2 также привязывает policy version/enforced bit к `ready` proof.

Java/Minecraft на Windows создаётся с `CREATE_SUSPENDED`, назначается в отдельный non-breakaway Job Object с `KILL_ON_JOB_CLOSE` и `DIE_ON_UNHANDLED_EXCEPTION`, после чего NeverRuntime проверяет membership/limits и только затем выполняет `ResumeThread`. Если любой шаг enforcement не подтверждён, launch прекращается fail-closed. Job handle удерживается supervisor-ом на всём времени жизни runtime, поэтому закрытие boundary завершает связанное process tree. `ProcessStatus.windowsProcessPolicy` показывает фактически применённую policy.

Java не получает `ProhibitDynamicCode`: HotSpot JIT требует динамически сгенерированный executable code. Строгие dynamic-code/image/child-process mitigations применяются к небольшому NeverGuard process, а Minecraft runtime изолируется process-tree policy без hooks/injection.

## NeverGuard Windows Integrity Evidence v1 — 0.13.2

`0.13.2` расширяет authenticated process boundary реальным Windows Integrity Evidence v1. Evidence собирается внутри отдельного `neverguard.exe` после успешного IPC handshake и теперь является обязательным fail-closed шагом перед Windows Minecraft launch. Guard независимо проверяет фактический parent PID, хэширует собственный executable и launcher process image, фиксирует размер/mtime/process creation time, выполняет локальную Authenticode-проверку через `WinVerifyTrust`, считывает process mitigation flags через `GetProcessMitigationPolicy` и строит fingerprint загруженного module set через Toolhelp snapshot.

Payload использует schema `neverguard/windows-integrity-evidence/v1`. Canonical core получает `evidenceSha256`, а затем guard привязывает digest к текущему authenticated IPC session key через HMAC `sessionProof`. Desktop повторно проверяет schema/version, PID boundary, SHA-256 и session proof перед использованием. Команда `neverguard_integrity_evidence` возвращает уже проверенный local payload; ошибка сбора или проверки блокирует `launch_minecraft`.

Это **local evidence**, а не server-verifiable attestation: Desktop участвует в локальной IPC session и текущая версия не использует TPM quote, отдельный device-bound attestation key, kernel measurement или remote verifier. Следующий server-verifiable этап должен добавлять собственную challenge/freshness/signature boundary и не выводить удалённое доверие только из `WinVerifyTrust` или process mitigations.

## NeverGuard Windows 0.13.1

`0.13.1` добавляет первый рабочий NeverGuard boundary для Windows. Guard — отдельный `neverguard.exe`; Desktop перед каждым Minecraft launch поднимает его и fail-closed требует успешный authenticated IPC handshake. Bootstrap secret генерируется на каждый запуск и передаётся guard как 32 raw bytes через унаследованный stdin, а не через argv/environment/файл.

IPC работает через local-only Windows Named Pipe со случайным endpoint. Взаимная HMAC-SHA-256 аутентификация использует client/server nonces и отдельный session key; каждый последующий request/response подписан MAC и защищён монотонным sequence от replay/out-of-order. В `0.13.1` доступны operational commands `ping`, `status`, `shutdown`; integrity evidence и server-verifiable guard attestation относятся к следующим этапам NeverGuard и здесь намеренно не заявляются.

Windows package собирается командой:

```powershell
./scripts/release/build-windows-desktop.ps1
```

ZIP содержит Desktop executable и обязательный соседний `neverguard.exe`; CI на `windows-2022` запускает реальный process-boundary integration test перед созданием release candidate.

## Device Trust Release 0.13.0

`0.13.0` завершает roadmap Device Trust и делает trust evidence частью официального подписанного release bundle. Схема не получает пустую migration: production baseline остаётся `0018_device_trust_stabilization_01210`, а Backend `/ready` и Device Trust E2E обязаны подтвердить её перед PASS.

Public matrix требует PostgreSQL lifecycle E2E и native Linux/Windows/macOS key-policy tests. Для официальной публикации `nl release publish-check` проверяет не только Minecraft Compatibility certification, но и `DEVICE_TRUST_TARGETS.json`, `DEVICE_TRUST_MATRIX.json`, `DEVICE_TRUST_CERTIFICATION.json`, привязанные к той же версии и source commit. `build-release.sh` принимает public matrix через `NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE`; без certification bundle остаётся release candidate.

Backend публикует machine-readable `deviceTrustRelease` contract в `/api/v1/auth/capabilities`: server-authoritative binding epoch, device-bound refresh, risk actions, Minecraft/ServerBridge enforcement, permanent revocation, dual-proof rotation и phishing-resistant recovery. P-256 protocol proof не выдаётся за vendor TPM/Secure Enclave provenance.

## Migration + stabilization 0.12.10

`0.12.10` является stabilization-релизом Device Trust schema и production-upgrade path. Migration `0018_device_trust_stabilization_01210.sql` исправляет PostgreSQL challenge-purpose constraint для реально используемых `key-rotate`/`key-recover`, переводит optional device references с empty-string sentinel на SQL `NULL`, нормализует безопасные legacy revoked/challenge states и затем устанавливает ownership/lifecycle constraints между trusted devices, auth sessions и Minecraft sessions.

Upgrade выполняется fail-closed: cross-user или структурно противоречивые связи не маскируются автоматическим repair, а останавливают migration до установки новых constraints. Отдельный `e2e/scripts/run-device-trust-migration-e2e.sh` воспроизводит exact `0.12.9` schema (`0001..0017`), применяет shipping CLI migration/verify и проверяет post-upgrade PostgreSQL enforcement. Public Device Trust matrix `0.12.10` принимает protocol PASS только вместе с evidence этого upgrade.

Для strict локальной проверки при наличии Docker/PostgreSQL client:

```bash
bash e2e/scripts/run-device-trust-migration-e2e.sh
bash e2e/scripts/run-device-trust-e2e.sh
```

## Device Trust E2E и публичная trust matrix 0.12.9

`0.12.9` добавляет отдельный production E2E для всей Device Trust цепочки и публичную CI-матрицу. `e2e/scripts/run-device-trust-e2e.sh` запускается против production-configured PostgreSQL/Redis Backend и реальными Ed25519/P-256 ключами проверяет registration/replay deny, binding epoch, signed refresh, dual-proof rotation, permanent fingerprint tombstone, ServerBridge invalidation, risk step-up, hardware-key challenge-response protocol, recovery prerequisite и revoke cascade.

Публичные цели находятся в `device-trust/targets.json` и не содержат ручного поля PASS/FAIL. Workflow `.github/workflows/device-trust.yml` запускает PostgreSQL protocol target и native Tauri/key-policy tests на Linux/Windows/macOS, после чего `scripts/device_trust/matrix.py` принимает только evidence той же версии, exact commit и Actions run ID. Итоговые `matrix.json` и `matrix.md` публикуются в Actions Summary и artifact. Aggregator дополнительно сверяет SHA-256 каждого заявленного evidence-файла; отсутствующий, изменённый, неполный или чужой result делает matrix failed.

Матрица не завышает assurance: CI P-256 case доказывает server-side challenge-response владение зарегистрированным ключом, но не vendor TPM/Secure Enclave provenance. Native platform targets доказывают compile/test path; headless runner не считается доказательством фактического OS secure-storage/HSM runtime конкретного устройства.

Локальная проверка definition/aggregator:

```bash
python3 scripts/device_trust/matrix.py validate --targets device-trust/targets.json
python3 scripts/device_trust/test_matrix.py
```

Production protocol E2E при наличии Docker/PostgreSQL client:

```bash
bash e2e/scripts/run-device-trust-e2e.sh
```

Подробности: `device-trust/README.md`.

## Кроссплатформенное усиление ключей 0.12.8

`0.12.8` добавляет production lifecycle для плановой ротации и восстановления потерянного device key. Rotation требует proof старым и новым ключом; recovery требует свежий phishing-resistant WebAuthn/passkey step-up и proof staged-новым ключом. Backend всегда создаёт новую device identity, увеличивает `binding_epoch`, оставляет старый fingerprint permanent tombstone и отзывает связанные старой identity sessions/refresh/Minecraft credentials.

Desktop/Tauri выполняет замену двухфазно (`stage → server ceremony → commit`) и умеет reconcile interrupted commit. Hardware P-256 ключи используют generation-specific labels, поэтому reset/rotation на TPM/Secure Enclave не переиспользует прежний ключ. При server-side revoke/missing device локальный key не уничтожается автоматически: используется recovery flow. API: `/api/v1/auth/devices/key-rotation/begin`, `/{deviceId}/key-rotation/complete`, `/key-recovery/begin`, `/{deviceId}/key-recovery/complete`.

## Minecraft / ServerBridge trust enforcement 0.12.7

`0.12.7` применяет Device Trust к самому игровому входу. Официальный `/api/v1/minecraft/session` требует active Never session, привязанную к verified trusted device, и допустимое risk decision. Minecraft credential сохраняет snapshot `trusted_device_id + binding_epoch`; ServerBridge join сохраняет тот же snapshot вместе с `project/profile/channel`.

При `validate`, Minecraft `join/hasJoined` и ServerBridge `validate-join/has-joined` Backend заново сверяет текущую parent session, device state, binding epoch и risk action. Re-bind или permanent revoke инвалидирует старый credential; `reattest` и `step-up` временно блокируют игровой вход до восстановления trust. Server-side plugin requests не изменяют IP/User-Agent risk игрока — они только применяют уже рассчитанное состояние. Legacy Yggdrasil authenticate остаётся совместимым, но фактический Minecraft `/join` без trusted device fail-closed, поэтому старый auth path не является bypass.

Migration `0016_minecraft_serverbridge_trust_0127.sql` добавляет persisted trust snapshot для `minecraft_sessions`. ServerBridge дополнительно проверяет `channel` наряду с project/profile. Velocity и Bukkit/Spigot/Paper/Purpur/Folia показывают конкретную причину trust deny и не имеют локального флага, отключающего Backend policy.

## Привязка сессии к устройству и интеграция риска 0.12.6

`0.12.6` связывает access/refresh lifecycle с реальным server-side состоянием trusted device. Persistent `binding_epoch` увеличивается при device bind/re-bind и входит в access JWT; Backend сверяет epoch, `device_id` и `device_trust` с текущей session, поэтому старый pre-bind token отклоняется сразу после смены binding.

Для bound-session `/api/v1/auth/refresh` теперь требует подпись текущим device key. Desktop выполняет её native-командой `sign_session_refresh`; signed payload содержит session/device/epoch и только SHA-256 refresh token. Risk engine хранит score/action (`allow|step-up|reattest|revoke`): network drift требует step-up на sensitive operations, stale hardware attestation — повторной attestation, а missing/revoked device или reuse refresh token приводит к revoke. PostgreSQL schema обновляется migration `0015_session_device_risk_0126.sql`.

## Device Management 0.12.5 — управление и необратимый revoke

`0.12.5` добавляет рабочий lifecycle trusted devices поверх Device Trust 0.12.1–0.12.4. `GET /api/v1/auth/devices?status=active|revoked` возвращает registry с признаком текущего устройства; `POST /api/v1/auth/devices/{deviceId}/revoke` необратимо отзывает конкретное устройство, а `POST /api/v1/auth/devices/revoke-others` сохраняет текущее verified device и отзывает остальные. Старый fingerprint после revoke остаётся tombstone и не может быть повторно зарегистрирован.

В PostgreSQL revoke выполняется транзакционно и каскадирует на Never sessions, refresh families/tokens, Minecraft sessions и незавершённые device challenges; связанные ServerBridge joins инвалидируются сразу после commit. Desktop показывает registry, умеет rename/revoke/revoke-others и при self-revoke удаляет local device key + auth session из OS secure storage. Admin registry/revoke доступен через `/api/v1/admin/auth/devices*`; admin revoke требует fresh phishing-resistant step-up. Новая migration не нужна — 0.12.5 использует уже существующую persistent schema и усиливает runtime semantics.

## Device Trust 0.12.4 — проверка challenge-response

`0.12.4` добавляет свежую проверяемую ceremony поверх hardware-bound P-256 identity из `0.12.3`. После обычного registration/session-bind Backend выдаёт уже привязанной сессии отдельный short-lived single-use attestation challenge. Tauri подписывает canonical `NeverLauncher Device Attestation v1` payload тем же non-exportable hardware key; software Ed25519 key в этот flow не допускается.

Успешная проверка сохраняет `attestationState=verified`, `attestationMethod=challenge-response-v1` и 12-часовое freshness window. Пока окно действительно, device assurance отражается как `challenge-response-attested`; после expiry API/JWT эффективно возвращают `proof-of-possession` до новой ceremony. Migration `0014_challenge_response_attestation_0124.sql` добавляет persistent state и purpose `attest` в существующий challenge registry.

Это подтверждает свежое владение зарегистрированным hardware key, но не подменяет vendor remote attestation: текущий signer API не даёт NeverLauncher TPM quote/Secure Enclave attestation certificate, поэтому `hardwareProvider` остаётся описательной metadata, а ответы явно содержат `hardwareProvenance=not-remotely-verified`. Device attestation не повышает RBAC/MFA/auth strength и не заменяет WebAuthn.

`0.12.3` остаётся базовым hardware identity layer: platform Secure Enclave/TPM → P-256 public key + ECDSA proof, с явным Ed25519/software fallback при отсутствии настоящего hardware backend.

## Device Trust 0.12.2

`0.12.1` добавил persistent registry и Ed25519 proof-of-possession; `0.12.2` доводит device key до официального Desktop-клиента. Tauri создаёт отдельный Ed25519 key для пары `Backend + canonical user`, хранит private seed только в native OS secure storage и подписывает server challenge внутри Rust boundary. React получает только public key/fingerprint/signature; private key не попадает в Backend, конфиг или `localStorage`.

После login Desktop автоматически выполняет регистрацию нового trusted device либо `verify/begin|complete` уже известного device id и сохраняет обновлённый access token с device claims в OS credential store. Revoke устройства по-прежнему отзывает связанные Never sessions/refresh families. Эта версия подтверждает software key possession + OS secure storage, но **не** заявляет hardware-bound identity/attestation — TPM/Secure Enclave/Windows Hello относятся к следующим этапам.

Production upgrade: `nl db migrate apply && nl db migrate verify`. Migration `0012_device_trust_core_0121` создаёт `trusted_devices`, single-use `device_challenges` и отдельную связь trusted device с `auth_sessions`.

## Minecraft Auth Compatibility 2.0

С `0.11.10` federation/migration stability является исполняемым release gate. `python3 scripts/test/federation-e2e.py` прогоняет Local/SQL/HTTP/OIDC/Microsoft/passkey через canonical session и Minecraft compatibility flow, а `bash e2e/scripts/run-federation-postgres-e2e.sh` проверяет restart и multi-instance refresh/revoke/replay на PostgreSQL. Перед production upgrade используйте `nl db migrate apply`, затем `nl db migrate verify`; verify fail-closed отклоняет unknown/future migrations, незапечатанные checksum и checksum drift.

С `0.11.9` login identity и Minecraft identity разделены. Local/SQL/HTTP/OIDC/Microsoft/passkey приводят к одному canonical Never user; из действующей Never session Desktop получает отдельную Minecraft session через `/api/v1/minecraft/session`. Игровой access token opaque и server-side хранится только в виде hash, а стабильный Minecraft UUID строится из immutable Never user ID, а не email.

NeverRuntime передаёт полученные UUID/token в реальный Minecraft launch. Если подписанный release manifest содержит `authlib-injector*.jar`, runtime подключает его как `-javaagent` к Backend, где доступны Yggdrasil-compatible `/authserver/*` и `/sessionserver/session/minecraft/*`. Начиная с 0.12.7 Minecraft token дополнительно привязан к trusted device и `binding_epoch`: re-bind/revoke/risk enforcement делает его непригодным для validate/join/hasJoined. ServerBridge применяет ту же live trust policy и pin project/profile/channel для защищённых серверов.

## Production-развёртывание

Основные файлы:

```text
deploy/production/docker-compose.yml
deploy/production/env.production.example
deploy/production/TLS.md
deploy/production/README.md
```

## CI

`.github/workflows/ci.yml` — обязательный CI candidate-контур: policy/contracts, Go, Admin/Desktop, NeverRuntime/Tauri, ServerBridge, production-контейнеры, release candidate bundle и PostgreSQL + Redis + actual Minecraft E2E. `.github/workflows/compatibility.yml` отдельно запускает все пять loader targets и публикует machine-verifiable matrix. Официальная публикация Minecraft Compatibility Release и новее выполняется только после передачи этой matrix в release build и успешного `release publish-check`; обычный candidate bundle сам по себе не считается Minecraft Compatibility Release.
