# Развёртывание production

> Не публикуйте API или панель в Интернет с тестовыми секретами. Следующие команды — последовательность подготовки, не гарантия успешного старта без настройки всех обязательных политик и подписей.

## Требования

- Linux/Docker Engine/Compose; PostgreSQL и Redis предусмотрены в `deploy/production/docker-compose.yml`.
- Публичное доменное имя и **TLS-терминация** на reverse proxy/ingress. Не передавайте bearer-токены через HTTP.
- Защищённое хранение секретов, план резервного копирования и обновления сертификатов.
- Подписанные release-артефакты, manifest signing private key, допустимые хеши Guard и ServerBridge.

## Подготовка

```bash
cp deploy/production/env.production.example deploy/production/.env
# Отредактируйте .env: пароли, URL, ключи, allowlists, origins, версии image tag.
bash scripts/install/production-setup.sh --env deploy/production/.env
```

Первый скрипт формирует подготовительный JSON-отчёт, **не выполняет всю установку**. Не публикуйте этот отчёт без редактирования: он содержит конфигурационные сведения. Перед запуском проверьте, что пустые обязательные параметры заполнены, а `change-me-*` нигде не осталось.

```bash
cd deploy/production
docker compose --env-file .env config   # проверить подстановку значений; вывод может содержать секреты
docker compose --env-file .env up -d --build
docker compose --env-file .env ps
```

Не сохраняйте вывод `docker compose config` в публичных логах. Контейнеры применяют миграции и политики согласно `deploy/production/docker-compose.yml` и конфигурации API. Для отказоустойчивости проверьте unique replica IDs и распределённые координаторы, а также ручной план миграций.

## Первый администратор и проект

Конкретные операции описаны в `schemas/openapi.yaml` (раздел `install`) и в CLI `nl install ...`. Устанавливайте администратора и первый проект после выполнения readiness/preflight; не используйте адреса/пароли из демонстрационных примеров в реальной системе.

## Проверка до публикации

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
# Полная сертификация (требуются toolchains и в некоторых режимах credentials/evidence):
NEVERLAUNCHER_PREFLIGHT_STRICT=1 bash scripts/release/preflight.sh
```

`/ready` и `/health` проверяйте на запущенном API, если эти маршруты доступны для вашей конфигурации. Для публичного релиза требуется evidence **точного commit SHA** — см. [сертификацию](../security/release-certification.md).

## Резервное копирование и обновления

Создайте подтверждённый backup PostgreSQL и содержимого storage до обновления, проверьте восстановление вне production, затем переходите к [процедуре миграции](../migration/upgrade.md). Закрывайте публичный доступ к данным и хранилищу через reverse proxy, auth и firewall.
