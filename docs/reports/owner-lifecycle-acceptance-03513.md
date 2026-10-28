# 0.35.13 Owner/G-M acceptance report — source implementation, 28 October 2026

## Реализованный рабочий продуктовый путь

- В существующем Admin Release Workspace владелец теперь инициирует подписанную публикацию/откат с серверным preview, фиксацией исходной ревизии channel head, сохранением mutation intent до сетевого вызова, точным idempotency replay при потере ответа и живой проверкой результата Backend.
- `job.status=succeeded` сам по себе не означает «релиз опубликован»: нужен фактически наблюдаемый channel head. Для rollback дополнительно требуется соответствие `job.result.packageId`. На `stable` job может быть успешным, но только staged; следующий шаг — продолжение новой подписанной сборки в server-owned черновике и полная runtime-сертификация.
- Устаревший прямой Admin publish убран из UI пакетов, вместо него используется единый мастер. Исходный backend protected release gate не ослаблен.
- Восстановлена работа исполняемого аудита G01–G35/M01–M19 на текущем `VERSION`, с историческим provenance и запретом подмены `targetVerified`.

## Локально проверено

- Полный Admin Node suite: **66/66 PASS** (включая **12/12** новых owner lifecycle тестов; структура настоящих authenticated API запросов, pending/failed/succeeded job, чтение channel head, отказ в неверных scope, защита от восстановления с чужим payload, staged rollback и server-backed draft continuation).
- Python acceptance runner tests: **11/11 PASS**, включая негативные отказы; audit: **54/54 записи G/M** с реальными исходниками и testRefs, **target verified = 0**.
- Локальные production Node регрессии существующего кода G31/M04/M07: **3/3 PASS**, отчёт помечен `local-regression-passed`, `realMinecraftCertification=false`.
- `python scripts/version/manage.py check`: **PASS**, версия 0.35.13 во всех обязательных метаданных.
- TypeScript/TSX синтаксис изменённых файлов проверен через TypeScript transpiler, без утверждения полного typecheck/React bundle.

## Не подтверждено / блокеры

- `npm ci --offline`: **FAIL**, отсутствует кэшированный `vite@8.0.14`. Полная сборка React/Admin не выполнялась, результаты внешнего CI неизвестны.
- Доступен Go **1.23.2**, backend требует **1.27.3**. Поэтому реальные full Go/API интеграционные тесты и серверные client lifecycle E2E локально **не выполнены**.
- Не выполнялись PostgreSQL HA, stable attestor, реальный Minecraft/ServerBridge, Windows/Linux/macOS Desktop и катастрофическое восстановление с проверкой всех пользовательских сценариев. **Ни один из 54 G/M сценариев не повышен до target-verified**.
- Это конкретное исправление повседневных owner workflow и регрессионного аудита, **не доказательство**, что все 54 исторические возможности полностью сертифицированы или что 0.36 GA готова.
