# NeverLauncher 1.0.0 — Supported Platform GA

## Состояние выпуска

Версия исходников **1.0.0** не является заявлением о фактическом прохождении GA. Публичную поставку допускает **только** успешно завершённая независимая приёмка на финальных нативных пакетах и точном неизменном исходном коммите. Отсутствующее доказательство даёт `BLOCKED`; заменять его манифестом, фикстурой или пропуском CI нельзя.

Поддерживаемые **кандидаты на нативную GA-сертификацию**: `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`. Эти имена не объявляют успешную сертификацию конкретного устройства, модпака, JVM или Microsoft-аккаунта. Фактические поддерживаемые возможности формируются из подписанного `GA_VERIFIED_SUPPORT_0440.json` только при прохождении всех проверок соответствующей платформы. Вендорские подписи, notarization и обязательные загрузчики должны быть проверены на нативных раннерах.

## Входящие доказательства и защищённое окружение

Нужен **закрытый** каталог, подготовленный независимым GA-аудитором `full-real-ga.yml`, вида:

```text
/private/ga1000-final/
  approval.json
  approval.sig
  source-index.json
  packages/
    launcher-1.0.0-<project>-windows-x64.exe
    launcher-1.0.0-<project>-windows-arm64.exe
    launcher-1.0.0-<project>-linux-x64.deb
    launcher-1.0.0-<project>-linux-x64.deb.asc
    launcher-1.0.0-<project>-linux-arm64.deb
    launcher-1.0.0-<project>-linux-arm64.deb.asc
    launcher-1.0.0-<project>-macos-x64.pkg
    launcher-1.0.0-<project>-macos-arm64.pkg
```

Все пакеты должны быть **настоящими уже подписанными финальными** файлами. В индексе должны совпадать версия, 40-символьный commit SHA, идентификатор проекта и хеши каждого файла. Вне входящего каталога и отдельно от GA-артефактов закрепите SHA-256 исходного индекса и SHA-256 DER независимого публичного Ed25519-ключа. Нельзя получать эти ожидаемые значения из того же недоверенного отчёта. Подписанное `approval.json` должно разрешать ровно E2E-01–18 и все точные пакеты.

Конфигурация защищённого GitHub окружения: переменные `NL_GA1000_VERIFIER_PUBLIC_KEY_PEM`, `NL_GA1000_VERIFIER_KEY_SHA256`, `NL_GA1000_INDEX_SHA256`, `NL_GA1000_PROJECT`; разрешённый вход `ga1000_evidence_run_id` должен указывать на успешный защищённый запуск GA для **того же** `github.sha`. Настройте отдельные роли и закрытые ключи `LAUNCHER_GA1000_*` на трёх независимых раннерах в `.github/workflows/full-real-ga.yml`. Доступ к секретам не должен переходить из лаборатории в публичный релиз.

## Проверка перед подписанием и после

При уже выполненных 18 E2E, 280 игровых комбинациях, шести нативных прогонах, независимых сборках, часовых испытаниях, подтверждённом закрытии P0/P1 и завершённой проверке подписей:

```bash
python3 scripts/release/publication_ga.py stage \
  --approval /private/ga1000-final/approval.json \
  --signature /private/ga1000-final/approval.sig \
  --verifier-public /private/keys/ga-verifier-public.pem \
  --verifier-pin "$INDEPENDENT_VERIFIER_KEY_SHA256" \
  --packages /private/ga1000-final/packages \
  --index /private/ga1000-final/source-index.json \
  --index-pin "$INDEPENDENT_SOURCE_INDEX_SHA256" \
  --bundle /absolute/unsigned/release-1.0.0 \
  --source-commit "$APPROVED_SOURCE_SHA" \
  --project "$APPROVED_PROJECT"
```

Этап существует **в рабочем коде** и является частью `build-release.sh` до формирования `RELEASE_MANIFEST.json`, `SHA256SUMS` и подписи Ed25519. Он проверяет независимую подпись и все исходные пакеты, переносит их без перезаписи и создаёт компактный `SUPPORTED_PLATFORM_GA_1000.json` по реально проверенным хешам. Файл включается в обязательные элементы подписанного выпуска. Повторная команда `verify` проверяет конечные байты, одобрение и его включение в релиз:

```bash
python3 scripts/release/publication_ga.py verify \
  --approval /private/ga1000-final/approval.json \
  --signature /private/ga1000-final/approval.sig \
  --verifier-public /private/keys/ga-verifier-public.pem \
  --verifier-pin "$INDEPENDENT_VERIFIER_KEY_SHA256" \
  --packages /private/ga1000-final/packages \
  --index /private/ga1000-final/source-index.json \
  --index-pin "$INDEPENDENT_SOURCE_INDEX_SHA256" \
  --bundle /absolute/signed/release-1.0.0 \
  --source-commit "$APPROVED_SOURCE_SHA" \
  --project "$APPROVED_PROJECT"
```

`publish.py` в ветке 1.0.0 повторяет указанную проверку и дополнительно требует завершения `required-production-ci`, независимой GA на шести платформах, подписанного манифеста и пробного запуска `release publish-check` **до** первого обращения к GitHub с правом записи. Go CLI отклоняет пакет, если один из этих девяти файлов не помечен в подписанном манифесте как `required` и не совпадает по SHA-256. Существует техническое ограничение: Python и Go не воспроизводят аппаратную нативную проверку подписи Windows/macOS на Linux — эта проверка должна быть выполнена соответствующими защищёнными раннерами.

## Допуск к публикации

Успех локальных unit/smoke-тестов, корректный YAML, наличие архива с исходниками или самостоятельная запись `status: PASS` **не** удовлетворяют условиям GA. Публикация остаётся заблокированной при любой открытой P0/P1, отсутствии независимых полномочий подписи, изменении входящих пакетов, несовпадении исходного SHA или если хоть одно обязательное CI-задание отменено/пропущено/ошибочно. Подлинное решение `PASS` возможно только после независимого завершения всего процесса и сверки финального публичного GitHub Release с утверждёнными байтами.
