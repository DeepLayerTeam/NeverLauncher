# HTTP API и OpenAPI

Канонический контракт: [`schemas/openapi.yaml`](../../schemas/openapi.yaml). Несмотря на расширение `.yaml`, содержимое текущего файла имеет JSON-представление OpenAPI **3.1.1** — поддерживайте это представление и существующий validator при изменениях.

Публичные области включают auth, minecraft-auth, install, projects, packages, admin, runtime, bridge, operations. Точные пути, модели, scopes, статусы и схемы ошибок необходимо брать непосредственно из контракта; нельзя восстанавливать их по примерам старых API версий.

## Проверка

```bash
python3 scripts/contracts/validate-openapi.py
# Генератор контрактов хранится в scripts/contracts/generate_openapi.py.
# Изучите его входные параметры перед запуском, чтобы не перезаписать схему.
```

Не перезаписывайте ручные правки с помощью генератора без diff/review. Синхронизируйте изменения сервера, клиента, DTO и SDK. Защищённые методы требуют авторизации и role checks. Для production используйте HTTPS, нужные CORS/CSRF политики и документированную ротацию ключей.

SDK и примеры находятся в `sdk/`, `examples/`, `scripts/sdk/generate-types.py`. Сценарии проверки: `scripts/contracts/validate-openapi.py`, Go-тесты Backend и интеграционные тесты. Список актуальных маршрутов определён `schemas/openapi.yaml`, а не только этим обзором.
