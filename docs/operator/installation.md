# Установка и первичная проверка

Работайте под выделенным административным пользователем с минимально необходимыми правами. Запишите исходную версию, SHA-256 дистрибутива, адрес будущего API, DNS, версию контейнерных образов, владельца данных, имя Compose project и место **внешнего** резервного копирования. Не копируйте секреты в shell history, issue, CI artifact или диагностический ZIP.

## Minimal — Linux, SQLite, локальные файлы

Необходимы проверенный `launcher-api`, подписанные Guard/Bridge-политики, Python 3.12+, пользователь службы и локальная файловая система. Пример пути бинарника замените действительным: команды сами не скачивают неизвестный исполняемый файл.

```sh
python3 scripts/install/minimal-install.py init \
  --root /var/lib/launcher-minimal \
  --binary /opt/launcher/bin/launcher-api \
  --public-url https://launcher.example.org \
  --guard-policy /etc/launcher/verified-guard.json \
  --bridge-policy /etc/launcher/verified-bridge.json
python3 scripts/install/minimal-install.py check \
  --env-file /var/lib/launcher-minimal/config/backend.env \
  --binary /opt/launcher/bin/launcher-api
# Запуск под владельцем службы через systemd; foreground только для контролируемой диагностики:
python3 scripts/install/minimal-install.py run \
  --env-file /var/lib/launcher-minimal/config/backend.env \
  --binary /opt/launcher/bin/launcher-api
```

На входящем reverse proxy отдельно настройте доверенный сертификат для того же origin и доступ к `https://launcher.example.org/ready`. Получите единственный bootstrap token из приватного `backend.env`, передайте его заголовком `X-Launcher-Bootstrap-Token` в существующую операцию `POST /api/v1/install/bootstrap-admin`; затем создайте первый проект через `POST /api/v1/install/first-project`. **Не печатайте токен в командной строке.** Проверьте вход, отказ повторного bootstrap, перезапуск API и сохранение проекта. [Подробности Minimal](../deployment/minimal-0375.md).

В действующем Minimal на хосте с приватным HTTPS URL:

```sh
python3 scripts/operations/operator_accept_04513.py live \
  --mode minimal --minimal-root /var/lib/launcher-minimal \
  --url https://launcher.example.org --version 0.45.13 \
  --report /var/tmp/launcher-minimal-acceptance.json
```

Скрипт читает обе базы SQLite только для проверки целостности, проверяет каталоги и публичное HTTPS `/ready`, но **не** создаёт администратора и не проводит restore.

## Standard — Docker Compose, PostgreSQL, TLS, первый администратор

Требуются Linux amd64/arm64, Docker Engine с Compose v2, Python 3.12+, OpenSSL, DNS, TCP 80/443, не менее 2 GiB RAM и 8 GiB места на Docker filesystem. Сертификат должен быть проверяемым системным хранилищем CA и соответствовать hostname, приватный ключ хранится только на хосте. Обязательные политики Guard/Bridge берутся из реального проверенного релиза.

```sh
sudo install -m 0600 deploy/production/env.production.example deploy/production/.env
# Заполните реальные секреты, публичный URL, TLS пути, POSTGRES_PASSWORD;
# LAUNCHER_IMAGE_TAG=0.45.13, LAUNCHER_DEPLOYMENT_MODE=standard.
sudo python3 scripts/install/production-deploy.py compose check \
  --mode standard --env deploy/production/.env
sudo python3 scripts/install/production-deploy.py compose up \
  --mode standard --env deploy/production/.env
```

Скрипт проверяет TLS и публичный `/ready`, но не создаёт администратора автоматически. Для первого администратора создайте приватный файл пароля с режимом `0600`; не передавайте пароль флагом:

```sh
sudo python3 scripts/install/production-deploy.py compose first-admin \
  --mode standard --env deploy/production/.env \
  --email operator@example.org --display-name Operator \
  --password-file /etc/launcher/initial-admin-password
```

Используйте свой адрес, удалите временный парольный файл после проверки входа/смены пароля и выполните MFA. Повторное создание владельца по bootstrap должно быть запрещено. Проверяйте `repository=postgres`, `storage=local`.

```sh
python3 scripts/operations/operator_accept_04513.py live \
  --mode standard --project launcher --env-file deploy/production/.env \
  --url https://launcher.example.org --version 0.45.13 \
  --report /var/tmp/launcher-standard-acceptance.json
```

## Network-HA — два API, два workers

Перед стартом подготовьте внешний долговременный PostgreSQL, Redis и S3, уникальные replica IDs, общее доверие, доступность bucket и защищённые внешние ключи. Отдельно проверьте обработку migrations с **единственным** writer и `LAUNCHER_DATABASE_AUTO_MIGRATE=false` на долгоживущих репликах. Не открывайте сеть с пустым хранилищем, пока restore и fencing не выполнены.

```sh
cd deploy/production
# .env: LAUNCHER_DEPLOYMENT_MODE=network-ha, LAUNCHER_IMAGE_TAG=0.45.13,
# действительные PostgreSQL/Redis/S3 credentials и TLS; chmod 0600 .env.
docker compose --env-file .env --profile network-ha \
  -f docker-compose.yml -f docker-compose.network-ha.yml \
  up -d postgres redis
docker compose --env-file .env --profile network-ha \
  -f docker-compose.yml -f docker-compose.network-ha.yml \
  run --rm --no-deps -e LAUNCHER_PROCESS_ROLE=migrate \
  -e LAUNCHER_DATABASE_AUTO_MIGRATE=true api
docker compose --env-file .env --profile network-ha \
  -f docker-compose.yml -f docker-compose.network-ha.yml \
  up -d --build api api-b worker-a worker-b admin nginx
cd ../..
```

Только после реального создания bucket, миграции и достижения готовности обоих API/workers:

```sh
python3 scripts/operations/operator_accept_04513.py live \
  --mode network-ha --project launcher --env-file deploy/production/.env \
  --url https://launcher.example.org --version 0.45.13 \
  --report /var/tmp/launcher-network-ha-acceptance.json
```

Проверка включает прямой `/ready` **в каждом из четырёх** API/worker-контейнеров, а не только Nginx. Наличие двух контейнеров на одном Docker-хосте не подтверждает переживание отказа хоста. [Подробности HA](../releases/0.45.5-multi-node-ha.md).

## После установки — вручную

Проверьте действительную версию, TLS hostname/chain, права владельца, MFA, создание и чтение проекта, загрузку/скачивание blob, вызов через один Go/TS/Java SDK, логи без секретов, восстановление тестовой копии на отдельном хосте. До включения пользователей выполните требования [контрольной ведомости](operator-checklist.md).
