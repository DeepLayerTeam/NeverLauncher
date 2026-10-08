# Public Device Trust Matrix

`device-trust/targets.json` — policy-файл NeverLauncher Device Trust CI. Он описывает обязательные targets и checks, но **не** хранит PASS/FAIL. Результат создаётся только из CI evidence для exact product version, Git commit и GitHub Actions run ID.

## Targets 0.13.0

## Device Trust Release certification 0.13.0

Каждый required target дополнительно обязан пройти `deviceTrustRelease0130`. Protocol target проверяет runtime `/api/v1/auth/capabilities`, `/ready` и sealed schema baseline `0018`; native targets запускают отдельный fail-closed key lifecycle test. Aggregate `matrix.json` используется как вход официальной release certification: `nl release build --device-trust-matrix ... --device-trust-targets ... --source-commit ...` создаёт `DEVICE_TRUST_CERTIFICATION.json`, а `nl release publish-check` для 0.13.0 отклоняет bundle без неё.


- `postgres-protocol-linux-x64` — production PostgreSQL Device Trust protocol E2E.
- `native-linux` — Tauri/device-key compile + key-policy unit tests на Linux runner.
- `native-windows` — тот же native boundary на Windows runner.
- `native-macos` — тот же native boundary на macOS runner.

Protocol E2E проверяет registration/replay protection, session binding epoch, device-bound refresh, dual-proof rotation, permanent fingerprint tombstone, ServerBridge binding invalidation, revoke cascade, risk step-up, P-256 challenge-response attestation protocol, обязательный phishing-resistant recovery prerequisite и успешный recovery после подписанной WebAuthn P-256 assertion ceremony.

Native targets проверяют compilation и security-policy tests существующего key lifecycle: OS-scoped key namespace, hardware backend fail-closed classification, generation-scoped hardware labels, canonical key replacement payload, refresh binding payload и attestation payload.

## Evidence boundary

Каждый target создаёт `device-trust-result.json`. `scripts/device_trust/matrix.py` fail-closed проверяет target identity, version, exact commit/run ID, обязательные checks, безопасные имена evidence-файлов, их фактическое наличие и SHA-256 каждого файла. Подмена или удаление лога/JSON evidence после выполнения target делает matrix failed. Для protocol target дополнительно обязательно `repository=postgresql`, `privateKeyServerExposed=false` и `vendorHardwareProvenance=not-verified`.

P-256 challenge-response в CI подтверждает корректность NeverLauncher protocol и владение зарегистрированным test key. Он не является TPM quote, Secure Enclave certificate или другим vendor remote-attestation proof. Native runner также не считается доказательством фактической работы защищённого хранилища/HSM на конкретном пользовательском компьютере.


### Migration stabilization evidence 0.12.10

Protocol target дополнительно требует `migrationStabilization01210`. Перед основным lifecycle E2E workflow воспроизводит exact `0.12.9` PostgreSQL schema (`0001..0017`) и запускает `e2e/scripts/run-device-trust-migration-e2e.sh`. Его `migration-stabilization.json` входит в hash-verified public evidence, поэтому агрегатор не принимает PASS, если upgrade `0.12.9 → 0.12.10` не выполнен или его evidence отсутствует/изменён.

Проверяется не только применение `0018`, но и исправление `key-rotate`/`key-recover` purpose constraint, NULL-normalization optional device references и DB-level deny для cross-user session/device, replacement и Minecraft trust links.

## Локальная проверка policy/aggregator

```bash
python3 scripts/device_trust/matrix.py validate --targets device-trust/targets.json
python3 scripts/device_trust/test_matrix.py
```

Production protocol E2E требует Docker и PostgreSQL client. Сначала выполняется exact-upgrade E2E, затем lifecycle E2E:

```bash
bash e2e/scripts/run-device-trust-migration-e2e.sh
bash e2e/scripts/run-device-trust-e2e.sh
```

Публичный workflow: `.github/workflows/device-trust.yml`. Агрегированные `matrix.json` и `matrix.md` публикуются в GitHub Actions Summary/artifact только из результатов текущего запуска.
