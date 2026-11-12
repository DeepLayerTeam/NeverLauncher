# 0.52.1 — исполняемая приёмка и защита подтверждающих данных

## Режимы и границы

`scripts/acceptance/inventory_0521.py` читает **сырые артефакты** `compatibility-*`, собранные из `e2e/scripts/run-compatibility-case.sh`. Он повторно проверяет `scripts/compatibility/matrix.py` и сами файлы JVM/loader/runtime, журналы, хеши, версию, исходный коммит, `GITHUB_RUN_ID` и `GITHUB_RUN_ATTEMPT`. Файлы не берутся из внешних произвольных URL, симлинки, двойные ключи JSON, дубликаты целей и подмены отвергаются. Принудительное изменение required в существующих матрицах ниже базового набора блокируется.

Сбор реальной матрицы выполняет существующий `.github/workflows/compatibility.yml`, включая все поддержанные ОС/архитектуры и Minecraft версии. Новое задание `acceptance-inventory-0521` перекачивает и **перепроверяет исходные** записи независимо от сводного `matrix.json`. Если хотя бы одна обязательная целевая платформа Minecraft не подтверждена, задание завершается с ошибкой и публикует отчёт BLOCKED. Для специализированного задания CI действует `--gate minecraft`; **общая** приёмка по умолчанию `--gate full` остаётся BLOCKED, пока не закрыты другие обязательные группы.

Для явного локального анализа:

```bash
python3 scripts/acceptance/inventory_0521.py inventory \
  --results-root /absolute/path/to/downloaded/compatibility-results \
  --commit 0123456789012345678901234567890123456789 \
  --run-id 123456 --attempt 1 \
  --output /absolute/path/to/unused/inventory-0521.json
```

Отчёт регистрирует 280 Minecraft + 14 ServerBridge + 7 Device Trust + 3 Guard + 18 E2E групп. **В 0.52.1 только реальная сырая Minecraft матрица может получить `observed`, остальные группы показываются BLOCKED до ввода и независимой проверки их реальных receipt в последующих версиях.** Все 12 optional Minecraft строк явно помечены `optional-unverified`. Нельзя превращать наличие manifest, зелёный unit-тест, матричную декларацию или один статус `passed` в доказательство реальной игры.

## Независимое подписание наблюдений

Оператор скачивает **сырые** `compatibility-*` из запуска CI для точного коммита. Проверяющий обязан самостоятельно получить отпечаток доверенного открытого ключа Ed25519. `public-key-sha256` — SHA-256 по DER SubjectPublicKeyInfo, передаётся из независимого доверенного канала; не принимать контрольную сумму из самой квитанции. Закрытый ключ reviewer (`0600`) хранится вне репозитория и вне CI. Подпись не требуется для публикации предварительной матрицы CI, но обязательна для статуса `independently reviewed`.

```bash
python3 scripts/acceptance/inventory_0521.py sign \
  --results-root /absolute/path/to/downloaded/compatibility-results \
  --commit 0123456789012345678901234567890123456789 \
  --run-id 123456 --attempt 1 --reviewer trusted-reviewer \
  --private-key /secure/offline/reviewer-private.pem \
  --public-key /secure/offline/reviewer-public.pem \
  --public-key-sha256 <PINNED_SHA256_FROM_DIFFERENT_CHANNEL> \
  --output /secure/unused/receipt-0521.json
python3 scripts/acceptance/inventory_0521.py verify \
  --results-root /absolute/path/to/downloaded/compatibility-results \
  --commit 0123456789012345678901234567890123456789 \
  --run-id 123456 --attempt 1 --reviewer trusted-reviewer \
  --public-key /secure/offline/reviewer-public.pem \
  --public-key-sha256 <PINNED_SHA256_FROM_DIFFERENT_CHANNEL> \
  --receipt /secure/unused/receipt-0521.json
```

Обе операции **требуют все 280 реально подтверждённых Minecraft-целей**. Проверка подписи повторно проходит все исходные данные и проверяет совпадение с подписанным набором; старый выпуск/run/attempt/catalog/log блокируется. Receipt не выдаёт `GA_PASS` и не подтверждает подписанные native installers. Подпись лишь подтверждает, что владелец независимого ключа принял связанный набор исходных наблюдений; она не исключает недобросовестного подписанта и не делает CI runner аппаратно доверенным.

**Для 0.53.0 по-прежнему обязательно** выполнить E2E-01–18 с реальными аккаунтами/игрой/миграциями/пакетами, 6 нативных установок, независимый ServerBridge/Guard/Device Trust аудит, restore и physical HA; никакая подмена runner сведениями из обычного JSON не считается выполнением.
