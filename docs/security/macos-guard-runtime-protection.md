# NeverLauncher 0.50.9 — защита среды выполнения Guard на macOS

## Запуск

При защищённом запуске Runtime и Desktop ProcessSupervisor **до допуска игры** запускают уже существующий macOS Guard (подписанный, Hardened Runtime, проверенный authenticated Unix IPC), требуют успешный ответ и привязывают наблюдатель к конкретному дочернему Java-процессу. Применяются `setpgid`, `RLIMIT_CORE=0` и удаление `DYLD_*` из окружения дочернего процесса. Невозможно продолжить запуск при неудачной проверке, без бесшумного понижения политики.

Нативный наблюдатель на Rust через `libproc` (`PROC_PIDTBSDINFO`, `proc_pidpath`) проверяет PID+время старта (защита от повторного использования PID), родителя, UID, группу процессов и признак трассировки. Сверяет канонический executable, device/inode и SHA-256; на старте и периодически перепроверяет `codesign --verify --strict`, TeamIdentifier и signing identifier. Для **JVM** требуется непустой Developer Team Identifier. Это намеренно отклоняет ad-hoc JDK; используйте корректно подписанный JRE. Проверка подписи не заменяет проверку notarization конечной поставки.

Проверенный Rust Runtime продолжает каждые пять секунд перепроверять подписанную политику Guard и SHA-256 включённых в сборку JAR, модов и нативных библиотек (существующие 0.50.2–0.50.8 проверки). После успешного допуска *heartbeat не перезапускает Guard*: его исчезновение, ошибка HMAC IPC, потеря JVM identity или недействительная подпись приводят к остановке защищённой игры. Устранены различия между разовым запуском и Desktop ProcessSupervisor.

## Реальные ограничения macOS

* На защищённом macOS невозможно законно и надёжно читать память **чужого процесса** с помощью `task_for_pid` без дополнительных entitlements/прав; этот релиз не утверждает, что перечисляет все загруженные Mach-O или все изменённые классы JVM.
* Проверка нативных библиотек по установленным файлам и отпечаткам кода, а также внутрипроцессные перехватчики Java не доказывают отсутствие полностью доверенного вредоносного кода внутри JVM. Именно поэтому серверный AntiCheat остаётся ведущим источником поведенческого сигнала.
* SIP и AMFI — контрольные механизмы ОС, но статус включённого SIP не доказывает чистоту игрового процесса. Нельзя отключать SIP, Gatekeeper или Hardened Runtime для работы Guard. CI собирает `csrutil status` только как diagnostic evidence, не как отдельный `PASS` защиты.
* Подписанная игровая Java не обязана иметь тот же entitlements/library validation, что Guard. JVM с JIT и разрешёнными native hooks имеет другую модель. Подпись JDK подтверждает его известного издателя и неизменность файлов, а не безопасность всех загруженных модов.
* `proc_pidinfo` может возвращать отказ вследствие ограничений ОС: ошибка не переводится в PASS. Для этого случая действует запрет защищённой игры при ошибке проверки.

## Проверки и критерии завершения

```sh
cargo check --manifest-path runtime/runtime/Cargo.toml --all-targets
cargo build --manifest-path runtime/runtime/Cargo.toml --bin runtime --bin guard
cargo test --manifest-path runtime/runtime/Cargo.toml --lib macos_runtime_guard_0509 -- --nocapture
python3 scripts/tests/guard_runtime_integrity_0505.py
python3 scripts/tests/continuous_game_protection_0506.py
```

В GitHub Actions добавлен job на `macos-15` (ARM64) и `macos-15-intel` (x64). Он проверяет настоящее `libproc`, проверенную подпись Java и реальную дочернюю JVM. На Linux эти проверки нельзя считать пройденными. На целевом Mac дополнительно нужны подписанная app/Guard поставка и реальный Minecraft/loader/join/long-run с разрешёнными модами/Java-агентами; пока этого нет, GA — BLOCKED.

Источники Apple: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution и https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_info.h
