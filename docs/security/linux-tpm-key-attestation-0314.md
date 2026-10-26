# NeverLauncher 0.31.4 — Linux TPM 2.0 Key Attestation

## Реализованный исполняемый сценарий

**Исходный device key не заменяется.** NeverLauncher сохраняет регистрацию `P-256/hardware/LinuxTpm` из `hardware-enclave` 0.2.10. При проверке Tauri перечитывает собственный OS keyring record, совпадение `userId/deviceId`, проверяет реальный Linux TPM signer и публичный ключ, затем читает TPM-wrapped `*.tpm_pub` и `*.tpm_priv` существующего ключа из XDG application key directory. Ни программный ключ, ни WSL Bridge, ни Linux Secret Service fallback, ни неподтверждённое имя TPM не получают remote provenance.

В Linux helper используется `tpm2-tools` 5.x, установленный из доверенных пакетов дистрибутива в `/usr/bin`. Запуски — отдельными argv без shell; код ограничивает время и размер файлов, проверяет UID, запрещает symlinks и удаляет приватную временную директорию. **`.tpm_priv` — зашифрованный TPM blob, а не экспортируемый приватный ключ.** Для загрузки используется точно заданный ECC P-256 parent в Owner hierarchy из `hardware-enclave` 0.2.10 (`SHA256`, `AES-128-CFB`, `restricted decrypt`, `fixedTPM/fixedParent/sensitiveDataOrigin/userWithAuth`). С `TPM2_Load` получается прежний подписывающий key, а не новый.

После `TPM2_ReadPublic` полная TPM2B_PUBLIC побайтово сверяется с сохранённой, а P-256 SEC1 — с серверной device identity. `TPM2_Certify` вызывается с отдельным TPM AK по persistent handle `0x81xxxxxx`, с `qualifyingData` — ровно 32-байтовым серверным nonce-derived SHA256. Клиент отправляет binary TPM2B_PUBLIC, TPM2B_ATTEST, TPMT_SIGNATURE и issuer-certified AK X.509 material в существующий `POST /api/v1/auth/devices/{id}/tpm-certify/complete` (после `begin`). Никакая локальная опция не выставляет `verified`: его присваивает только сервер.

0.31.4 исправляет реальную несовместимость с 0.31.2: `hardware-enclave` Linux создаёт signing key `TPMT_ECC_SCHEME=ECDSA(SHA256)`, тогда как Windows ранее проверял `NULL`. Общий бинарный парсер и Go verifier теперь принимают **только** `NULL` или `ECDSA(SHA256)`; SHA-1, остальные схемы и кривые остаются запрещёнными. TPM Name пересчитывается из полной фактической public area, включая scheme/hash, поэтому чужой объект не может пройти проверку по голому public key.

## Требования оператора

1. Linux glibc, устройство `/dev/tpmrm0`, права текущего пользователя на TPM resource manager, установленный `tpm2-tools` 5.x, `libtss2` (зависимости tss-esapi/hardware-enclave). На системах, где нет этих условий, отображается конкретный отказ, без software fallback к remotely-verified trust.
2. *Существующий зарегистрированный* аппаратный device key: backend `LinuxTpm`, P-256. Для уже зарегистрированного software-key необходим явный стандартный процесс ротации на hardware key, а не скрытая замена внутри attestation.
3. Раздельный **настоящий TPM-backed AK**, предварительно provisioned в NVRAM TPM под разрешённым persistent handle, например `0x81010001`. Его issuer должен независимо подтвердить происхождение AK в TPM и выдать **не-CA** X.509 leaf c `DigitalSignature`. NeverLauncher не создаёт локальный самоподписанный CA/AK и не принимает предоставленный клиентом PEM в качестве root of trust.
4. На Backend: `NEVERLAUNCHER_TPM_AK_ROOTS_FILE`, активная policy с Linux в разрешённых платформах и доверенным AK CA, как в `tpm-certify-verifier-0312.md`. Должна работать ротация/отзыв root/AK.
5. Открыть **Вход → Windows/Linux TPM Key Attestation**, ввести `0x81xxxxxx`, PEM AK и (при необходимости) intermediates; нажать «Подтвердить TPM-происхождение». Приватный AK/EK никогда не вводится в UI. TPM objects, требующие нестандартной policy/nonempty auth, отвергаются без повышения уровня доверия.

## Гарантии и ограничения

- Отдельно проверяются native public area, `TPM2_Certify` подпись AK, привязка к server nonce/device/user/session/binding epoch, срок действия, одноразовость, CA root, revocation. Ответ сервера — единственный источник аппаратного assurance.
- Проверки **не** означают measured boot/PCR/Guard runtime integrity и не заменяют античит. `strict` по-прежнему требует независимых проверок Guard и отвергается без них.
- Смена подписи программного пакета или имени key directory не повышает доверие. Неподдерживаемые kernel/TPM credentials возвращают actionable refusal.
- Текущий Linux producer требует пустую TPM password authorization для user key и AK и AK с persistent handle. Варианты с password/PolicyAuthorize или AK в непостоянном контексте не поддерживаются. Отказ не является общим сбоем лаунчера.
- Код защищает от случайного доступа к wrapped blob и недоверенных CLI параметров, но **не обеспечивает изоляцию от root или malware с правами того же пользователя**.

## Проверка

Выполнить на Linux со средой сборки и dev-пакетами Tauri/tss-esapi:

```sh
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml tpm_linux_0314
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml tpm_wire_0313
cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml
(cd services/api && go test -race ./internal/attestverify ./internal/trustbaseline)
```

Аппаратная приёмка обязательна отдельно: реальный TPM 2.0 и выданный TPM AK сертификат не менее двух поставщиков; пройти полный цикл `begin → TPM2_Certify → complete → status`; негативные пробы с чужим AK/subject, несовпадающим ключом, отсутствующим TPM, неправильным parent, повторённым nonce, сменой epoch, отозванным AK/root, истекшим challenge и policy-required AK. Наличие CI без физического TPM **не доказывает успешность этих испытаний**.
