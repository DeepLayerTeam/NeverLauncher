# Сертификация и поставка релиза

## Обязательные проверки

1. Версия в `VERSION`, файлы блокировки зависимостей и схемы согласованы.
2. Файл `schemas/openapi.yaml` проходит проверку контракта.
3. Автономные проверки подтверждают инварианты безопасности, а не простое наличие комментариев.
4. Успешны тесты Go, Rust, TypeScript и Java; реальные клиент Minecraft и загрузчик прошли предписанные матрицы.
5. Сформированы и проверены сертификаты и подтверждающие материалы для **этого SHA коммита**, ОС и архитектуры.
6. Манифесты, пакеты, Guard, Bridge, JRE и артефакты релиза подписаны согласно политике поставки.
7. Перед публикацией выполнены предварительная проверка рабочего окружения, резервное копирование и дымовые тесты.

## Локальные проверки контрактов

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
python3 scripts/release/test_fetch_exact_certifications.py
python3 scripts/smoke/offline/repository-policy.py
```

`LAUNCHER_PREFLIGHT_STRICT=1 bash scripts/release/preflight.sh` запускает строгие проверки с учётом платформы и установленного набора инструментов. `scripts/release/fetch-exact-certifications.py` работает с сертификатами GitHub и не должен передавать bearer-токен авторизации на адреса хранения артефактов. Не включайте токены в публичные URL.

## Принцип достоверной сертификации

Отсутствующее, просроченное, подменённое, не соответствующее SHA или неуспешное подтверждение **запрещает** помечать выпуск как сертифицированный. Результат PASS нельзя получать путём исключения обязательных тестов или отключения Guard. Особое внимание уделяйте `.github/workflows/compatibility.yml`, `.github/workflows/device-trust.yml`, `.github/workflows/extensions-ga-0210.yml`, `.github/workflows/production-release-candidate.yml`.

См. [устранение неполадок CI](../troubleshooting/ci.md) и [матрицу совместимости](../../COMPATIBILITY.md).

## Проверка допуска Profile/Workspace 0.23.0

`python3 scripts/release/certify-profiles-ga-0230.py` запускает реальные модульные, HTTP- и PostgreSQL E2E-тесты с детектором гонок Go и отклоняет результат при отсутствующих или пропущенных сценариях. Необходимы `LAUNCHER_TEST_POSTGRES_DSN` и точный SHA исходного кода. Для кандидата в рабочий релиз обязателен успешно пройденный сертификат, привязанный к текущему коммиту. См. [приёмку профилей и рабочих областей](../releases/profile-workspaces-0230.md).
