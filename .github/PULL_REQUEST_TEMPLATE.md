## Изменение

Кратко: что меняется и зачем? Укажите связанные issues (`Fixes #...`) при наличии.

## Область и совместимость

- [ ] Изменения ограничены необходимыми файлами; `VERSION` не меняется без отдельной release-задачи.
- [ ] Оценено влияние на API/OpenAPI, миграции, Desktop, Minecraft/loader, ServerBridge и NeverExtensions.
- [ ] Для изменений поведения обновлена документация в `docs/` и/или корне репозитория.
- [ ] Не ослаблены подписи, NeverGuard, attestation, token checks и fail-closed guards.

## Проверки (перечислить результат или причину пропуска)

- [ ] `python3 scripts/version/manage.py check`
- [ ] `python3 scripts/contracts/validate-openapi.py`
- [ ] Относящиеся к изменению Go/Rust/Node/Java тесты
- [ ] Нужные платформенные/integration/e2e тесты (указать ОС и SHA)
- [ ] Нет секретов, персональных данных, generated build artifacts или локальных `.env` в diff

## Доказательства и ограничения

Приложите обезличенные логи, ссылки на GitHub Actions и шаги воспроизведения. Если сценарий не удалось проверить (нет Java/Windows/macOS/upstream), укажите это явно. **Не утверждайте, что весь CI зелёный, пока не завершились обязательные jobs на этом SHA.**
