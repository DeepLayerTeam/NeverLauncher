# Секреты, подписи, API/SDK, миграция

## Работа с секретами

- `deploy/production/.env`, private key TLS, Ed25519 signing seed, bootstrap token, recovery key, S3/PG/Redis credentials и секреты внешних провайдеров — разные объекты, с раздельной ротацией и запретом публикации в Git/CI/ZIP диагностики.
- `minimal backup-portable` включает конфигурацию и секреты **внутри зашифрованного архива**, но ключ восстановления хранится отдельно. Standard/Network-HA DR **не** сохраняет автоматически `.env`, TLS и ключи; возвращайте их из доверенного secret manager.
- Потеря доверенного signing root без контролируемой ротации может нарушить доверие существующих клиентов. Слепая генерация новых ключей после восстановления не является recovery.
- Оператор проверяет права `0600` приватных файлов, системные CA, hostname и срок сертификата; не использует `curl -k` и не отключает TLS verification.

## Подписанный выпуск

Сначала реальная сборка и платформенная подпись, затем окончательная упаковка, проверка **конечных байтов**, независимые runtime/GA результаты, BOM, SPDX 2.3 SBOM, SLSA provenance, release manifest и подпись. Шесть целей: Windows/Linux/macOS × x64/ARM64. Проверка Linux не подтверждает Windows/macOS. Отсутствующий сертификат, подпись, hardware runner или игровой E2E — выпуск заблокирован.

Проверяйте CLI `launcher release distribution-verify` и `launcher release verify` по [Signed Distribution](../releases/0.45.11-signed-distribution.md). Для брендирования сохраняйте project identity и pinned trust root по [Branding GA](../releases/0.45.10-branding-ga.md). Установщик не должен автоматически переключаться на новый release при ошибке подписи или запуска.

## API/SDK

Канонический `schemas/openapi.yaml`: OpenAPI 3.1.1, контракт `1.0.0`, 452 операции из baseline 0.45.12. `sdk/api/go`, `sdk/api/typescript`, `sdk/java/http-client` отправляют реальные HTTP-запросы; это **не** 452 полностью типизированных индивидуальных методов. Обратная совместимость с 0.45.11 требует live-проверки (сравнение OpenAPI и мок-запросы недостаточны). [API/SDK Freeze Candidate](../releases/0.45.12-api-sdk-freeze-candidate.md).

```sh
python3 scripts/contracts/validate-openapi.py
python3 scripts/contracts/compatibility_04512.py
python3 scripts/sdk/generate-http-operations.py --check
```

## Миграция Gravit

Перед миграцией выполняйте inventory, dry-run, фиксируйте поддерживаемые password verifiers, UUID, OptionalView и модули. Старые Gravit-сессии, незнакомые хеши и произвольные сторонние JAR нельзя автоматически объявлять совместимыми. Перед cutover нужен восстановимый snapshot, проверка real Minecraft join и явная точка возврата. [Runbook Gravit Migration GA](../migration/gravit-migration-ga-0450.md).
