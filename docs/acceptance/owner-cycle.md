# Launcher 0.39.0 — реальная приёмка владельца через Admin

Это **исполняемый сценарий**, не декларация готовности. Для допуска 0.39.0 `scripts/release/certify-admin-ga-0220.sh` требует запуск `e2e/scripts/owner-cycle-0390-browser.py` и точную привязку `owner-cycle-0390.json` к `admin-0220.json`. Отсутствие окружения, любой отказ или неполный результат блокируют сертификат.

## Развёртывание

1. На **одноразовом** изолированном стенде развернуть Admin и PostgreSQL Backend из того же commit и версии, что кандидат. В `E2E_EXPECTED_COMMIT` указать точный SHA checkout; для Backend `/api/v1/status` и метатег Admin `launcher-source-commit` должны вернуть тот же SHA. Сертификатор дополнительно проверяет действующие правила выпуска, тесты, Go и Vite сборки.
2. Создать проект с профилем и каналом; в нём **две реальные immutable-сборки**: одна проверена и допущена к публикации согласно действующей политике (включая trusted runtime evidence, если канал это требует), вторая не допущена. Подготовить через Admin сохранённые release-drafts с разными версиями, привязанные к этим пакетам. Не заменять runtime evidence имитациями и не создавать искусственные PASS.
3. Обеспечить уже опубликованную более старую версию в канале для rollback. Если политика stable разрешает только staged rollback, выполнить его штатную независимую сертификацию или использовать отдельный проверенный канал, где rollback действительно переключает указатель. Сценарий **не засчитывает staged rollback за выполненный**.
4. Установить Playwright с Chromium и переменные окружения: `E2E_ADMIN_URL`, `E2E_API_URL`, `E2E_ADMIN_TOKEN`, `E2E_OPERATOR_TOKEN`, `E2E_FOREIGN_PROJECT_ID`, `E2E_EXPECTED_COMMIT`, `E2E_OWNER_PROJECT_ID`, `E2E_OWNER_PROFILE_ID`, `E2E_OWNER_CHANNEL`, `E2E_OWNER_VALID_PACKAGE_ID`, `E2E_OWNER_BROKEN_PACKAGE_ID`, `E2E_OWNER_VALID_DRAFT_VERSION`, `E2E_OWNER_BROKEN_DRAFT_VERSION`, `E2E_OWNER_ROLLBACK_VERSION`, `E2E_OWNER_DESTRUCTIVE_ACK=OWNER_0390_DISPOSABLE_STAGING`. Для полноценной работы административные токены должны иметь необходимые реальные права и MFA; сценарий не подменяет MFA.
5. Выполнить `python3 e2e/scripts/owner-cycle-0390-browser.py`. Скрипт через **реальный UI** создаёт проект/профиль, проверяет отрицательную публикацию, публикует допущенную сборку, перезагружает страницу и восстанавливает исходное задание, сверяет channel head, делает rollback и проверяет отказ в доступе к чужому проекту. Проверки состояния выполняются чтением Backend API; мутации производятся через Admin. Прогон оставляет тестовый проект в **одноразовом** стенде.

На успешном прогоне `dist/ga-certification/owner-cycle-0390.json` содержит восемь фактических проверок, идентификаторы ресурсов и начальную/конечную ревизию канала с разницей 2. Неуспешный запуск не выдаёт PASS. Итоговый JSON — **CI evidence**, не операторская криптографическая подпись и не замена обязательной матрицы платформ/игровых запусков.

## Локальные проверки без стенда

`npm test` в `apps/admin`, `python3 -m unittest scripts/release/test_owner_cycle_0390.py -v`, `python3 scripts/version/manage.py check`, `python3 scripts/contracts/validate-openapi.py`. Они проверяют код и правила, **но не являются browser E2E**. Production-сертификат остаётся заблокированным до настоящего исполнения.
