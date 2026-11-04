# 0.43.1: проверяемое доказательство безопасности перед GA

Этот документ описывает **действующий** production release gate, а не разрешение
отмечать функцию как реализованную. `VERSION=0.43.1` не означает сертификацию:
её выдаёт только успешная независимая проверка завершённых запусков и
окончательных установщиков. Пока доказательств нет, GA блокируется.

## Что проверяет gate

`scripts/ga/verified_targets.py` сохраняет старый Ed25519-домен `launcher.ga.targets.v2\0`
и неизменённые проверки шести точных файлов. Начиная с 0.43.1 к 15 обязательным
проверкам каждой платформы добавлены шесть **отдельных** security checks:

| Check | Разрешённая операция | Обязательный отказ | Где проверять |
|---|---|---|---|
| `securityDeviceTrust` | `deviceEnrollmentAllowed` | `staleDeviceEpochDenied` | Нативный клиент + backend |
| `securityHwidPolicy` | `knownDeviceLoginAllowed` | `unapprovedHardwareChangeDenied` | Нативный клиент + backend |
| `securityNeverGuard` | `protectedGameJoinAllowed` | `tamperedGuardJoinDenied` | Desktop → игра → сервер |
| `securityKeyRevocation` | `currentKeyJoinAllowed` | `revokedKeyJoinDenied` | Backend + игровой сервер |
| `securityAccountRecovery` | `newDeviceRecoveryAllowed` | `oldRecoveryKeyDenied` | Клиент + backend |
| `securityNativeSandbox` | `authorizedExtensionBrokerAllowed` | `unauthorizedExtensionAccessDenied` | **Backend native extension host**, не Desktop |

Это минимальные обязательные наблюдения; другие проверки предыдущих релизов
не отменены. Их список **зашит в верификатор**, его нельзя сократить из
`targets.json`, receipt, переменной окружения или произвольного манифеста.
Поддержка каждого target фиксируется отдельно: Windows/Linux/macOS × x64/ARM64.
Нельзя выдавать запуск под эмуляцией за native ARM64; положительный запуск
игры не подтверждает hardware-attestation или песочницу игрового Java Hook.

## Входной формат

Независимый оператор подписывает `evidence/approval.json` и
`evidence/approval.sig` на закреплённом Ed25519-ключе с доменом GA v2.
`targets[*].checks` подписанного документа обязательно включает SHA-256
**каждого** из шести отчётов на каждой из шести платформ.

В каталоге `evidence/targets/<target>/` требуются:

- `<check>.json`: структура `launcher.security.capability.0431.v1`, версия,
  commit, target, check, `actualExecution=true`, `simulated=false`, `status=passed`,
  хешы **окончательных** binary/package, `executionId`, `runId`, `runAttempt`,
  область выполнения, UTC-время, SHA-256 журнала и пара независимых наблюдений
  с исходами `allowed` и `denied`.
- `security-0431/<check>.jsonl`: два исходных machine-readable наблюдения
  `launcher.security.observation.0431.v1`, точно соответствующие
  correlation ID, версии запуска CI, целевому пакету, времени и требуемым
  решениям. Без сырого журнала одно поле `passed` не принимается.

Формат выполняет **проверку происхождения, полноты и целостности записей**;
он сам не может криптографически доказать, что человек действительно играл
в Minecraft или что аппаратный TPM не эмулирован. Не следует делать такие
утверждения без независимого нативного запуска и аппаратной аттестации.
Секреты, пользовательские Hardware ID, токены и закрытые ключи не должны
попадать в общедоступный архив исходных наблюдений.

## Подключение к выпуску

`build-release.sh` дважды проверяет данные: до затратной сборки (`--preflight`)
и после упаковки для **точных** байтов (`--bundle`), а затем формирует
`SECURITY_CAPABILITY_EVIDENCE_0431.zip`. Доказательства, их операторская
подпись, receipt и ZIP попадают в общий подписанный release bundle **до**
`SHA256SUMS.sig`. При публикации `publish_0370.py` повторно читает ZIP,
проверяет набор файлов, совпадение подписи/отчётов/журналов и актуальные
`GITHUB_RUN_ID` + `GITHUB_RUN_ATTEMPT`.

Обязательные отказы: нет хотя бы одного требуемого отчёта, `SKIP/BLOCKED`,
содержимое журнала изменено, отрицательный сценарий неожиданно разрешён,
чужая ОС/архитектура, чужой пакет/SHA, старый/будущий run, неверная подпись,
другая эпоха CI или отсутствие архива в release bundle. При любом из них
**не выдавать GA-сертификат и не публиковать релиз**.

Содержимое тестовых фикстур `test_security_capabilities_0431.py` — только
тестирование verifier; оно не должно использоваться для сертификации.
Реальные исходные журналы должны поступать от нативных исполнителей с
проверяемыми отладочными, серверными и OS-наблюдениями и утверждаться
отдельным оператором. Успех этих Python-тестов **не** подтверждает
готовность платформенных защит. До получения live evidence статус GA закрыт.
