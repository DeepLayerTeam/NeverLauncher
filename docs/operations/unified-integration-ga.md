# Unified Integration GA — NeverLauncher 1.3.0

Обновление исходников 1.2.5 → 1.3.0. Сборка и публикация выполняются на CI владельца. Существующие Keycloak client ID, ключи Stable/Beta, компонентные ключи, правила RBAC/MFA, лимиты AI и миграции сохраняются. Пересоберите Backend, Admin Panel и Desktop; новый SQL-формат не вводится.

## Совместная работа Desktop

- Установка обновления использует эксклюзивную нативную блокировку `OPERATIONS`. Авторизация, MFA, управление идентичностями, работа с OS keyring и нативная AI-генерация получают разделяемую блокировку. Пока они идут, проверенный пакет не извлекается из памяти для установки. Закончите/отмените операцию и повторите установку; загрузка может продолжаться независимо. Это внутрипроцессная блокировка, а не гарантия синхронизации нескольких независимых процессов Desktop.
- AI-операция привязана к namespace OS keyring и session ID. При локальном выходе/удалении, подтверждённом отзыве или неудачной ротации отменяется соответствующий локальный поток, в том числе при недоступном Backend. Отмена другого аккаунта или Backend не затрагивает этот поток. Уже отправленный запрос может быть оплачиваемым; неизвестный usage сохраняет полный резерв.
- Пока браузер открыт для привязки, токен может обновляться. Перед завершением привязки Desktop повторно считывает сессию под общей блокировкой авторизации и отклоняет смену пользователя/сессии. Сервер по-прежнему проверяет владение, состояние и подтверждение.
- AI Gateway и Copilot используют канонический NeverLauncher user ID, а не email внешнего провайдера. Авторизация и проверка доступа выполняются на Backend; model output не обладает полномочиями исполнения. Установка не зависит от наличия AI-ключа и не требует входа.

## Обязательный автоматизированный gate

`.github/workflows/unified-integration.yml` запускается на изменениях подсистем и вызывается обоими production release workflows. Требуются все четыре job: `identity`, `gateway`, `copilot`, `desktop-and-delivery`. Проверяется SHA checkout, номер версии, итог каждого задания; skipped/cancelled/absent/failure не проходят. Отчёт `unified-integration-evidence.json` привязан к версии, SHA, run ID и attempt. Это отчёт автоматизированного CI, а не независимая аттестация реальных машин.

Проверяются: OIDC/локальная MFA и браузер Admin; AI HTTP/SSE, реальные SQLite/PG бюджеты; подтверждение Copilot; Desktop TypeScript, Rust и Go recovery на Windows/Linux/macOS; подписи, каналы и шесть вариантов доставки. Новый `TestUnifiedIntegration130CrossClientLifecycle` использует реальный HTTP Backend и SQLite ledger, но IdP и OpenAI заменены тестовыми внешними сервисами. Он проверяет общий бюджет двух сессий, отказ по RBAC, ротацию, отзыв и сохранение резерва зависшей генерации. Нативный тест `unified_auth_ai_update_exclusion` проверяет взаимное исключение операции установки и общих операций; Rust-тесты проверяют отмену только правильной сессии.

Локальные команды:

```sh
python scripts/version/manage.py check
python scripts/contracts/validate-openapi.py
python -m unittest discover -s scripts/ci -p test_required_jobs.py -v
python -m unittest discover -s e2e/scripts -p test_unified_ai_smoke.py -v
(cd services/api && go test -race -count=1 ./internal/httpapi -run 'TestUnifiedIntegration130|TestSkif4erGA110|TestCopilot')
(cd services/api && go test -race -count=1 ./internal/aigateway)
(cd apps/admin && npm ci && npm test && npm run build)
(cd apps/desktop && npm ci && npm run test:auth-experience && npm run test:native-update && npm run test:ai-chat && npm run test:ai-diagnostics && npm run build)
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml native_updater --no-default-features
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml desktop_auth --no-default-features
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml skif4er_login --no-default-features
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml ai_chat --no-default-features
```

Используйте toolchain из репозитория; не понижайте версии для обхода проверок. Для полного CI необходимы зависимости Tauri, Chromium и отдельная PostgreSQL БД.

## Реальная приёмка перед GitHub Release Delivery

Разверните Backend и Admin на выделенном HTTPS staging с точным исходным коммитом релиза. При сборке Backend передайте `LAUNCHER_SOURCE_COMMIT=$(git rev-parse HEAD)` и версию из `VERSION` (см. production Compose). Endpoint `/api/v1/status` должен возвращать `version=1.3.0`, `sourceCommit=<точный SHA>` и `status=ok`. Зарегистрируйте точный HTTPS redirect URI staging Admin в Keycloak. Используйте заранее привязанный отдельный тестовый аккаунт, которому разрешён AI, с ненулевым бюджетом. Не используйте рабочую учётную запись администратора; не запускайте другие AI-запросы от staging-аккаунта одновременно.

Создайте защищённый GitHub Actions Environment `unified-staging` (только main, обязательное одобрение владельца). В нём задайте:

| Тип | Имя | Значение |
| --- | --- | --- |
| Variable | `SKIF4ER_E2E_ADMIN_URL` | HTTPS адрес staging Admin |
| Variable | `SKIF4ER_E2E_BACKEND_URL` | HTTPS адрес staging Backend |
| Variable | `SKIF4ER_E2E_CANONICAL_USER_ID` | ID отдельного привязанного аккаунта |
| Secret | `SKIF4ER_E2E_USERNAME` | Логин Keycloak тестового аккаунта |
| Secret | `SKIF4ER_E2E_PASSWORD` | Пароль тестового аккаунта |
| Secret | `SKIF4ER_E2E_RECOVERY_CODE` | Одноразовый код, если локальная MFA требует его; обновлять перед следующим запуском |

OpenAI API key и тарифы настраиваются только на staging Backend, не в workflow. Smoke предполагает стандартную форму Keycloak; для дополнительных upstream MFA/нестандартных форм требуется отдельная интерактивная приёмка или адаптация автоматизации. Не ослабляйте MFA ради теста.

`python e2e/scripts/skif4er-admin-e2e.py --live --live-ai` после явного разрешения использует реальный вход, сверяет канонический ID и SHA, обновляет сессию, делает ровно один потенциально платный запрос с безвредным prompt, сверяет итог SSE и прирост учёта расходов, выходит и проверяет отказ AI после отзыва. Без автоматических повторов, без записи токенов/трассировки/скриншотов. Для локального запуска задайте также `SKIF4ER_E2E_SOURCE_COMMIT` (SHA проверяемой сборки). При ошибке проверьте бюджет и статус сессии; не повторяйте запрос до выяснения результата.

## Публикация

1. В защищённой ветке `main` запустите GitHub Release Delivery с `publish=false` и нужным `channel` (никаких платных live-запросов). Дождитесь успешных проверок и сборки шести подписанных пакетов.
2. На реальных поддерживаемых Windows, Linux, macOS проверьте установку 1.2.5→1.3.0, восстановление сессии, генерацию, блокировку установки при активном входе/AI, успешную установку после отмены, обновление с обрывом сети и отказы при неверной подписи/канале. Подтвердите MFA/RBAC Copilot. Архитектуры x64/ARM64 требуют собственной нативной приёмки. Не выдавайте fixture- или unit-тесты за эти испытания.
3. Убедитесь, что production/staging настройки и ключи доверия корректны. Запустите workflow `publish=true`. Требуются `unified-tests`, `sign-and-verify`, успешный `live-acceptance` и одобрение `production-publish`. Затем выполняется публичная проверка всех шести файлов. Stable/Beta изолированы; опубликованные байты не заменяются. Полный исторический production candidate workflow также требует unified CI и сохраняет существующие независимые аттестации.

Никаких production-ключей или подтверждений приёмки в исходном архиве нет. До успешных сборок, реальной приёмки и публикации статус версии — кандидат, а не подтверждённый GA.
