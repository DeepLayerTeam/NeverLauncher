# 0.45.14 — независимая приёмка: работающие операции

**Область:** один независимый оператор лично запускает четыре реальные операции: чистую установку **Standard**, обновление работающего **Standard** с 0.45.13 до 0.45.14, восстановление Standard-снимка на другом Linux-хосте и проверку отказов **изолированного Network-HA**. Это проверка действующих сервисов, а не контракт, ведомость или имитация. Полноценная приёмка Minimal, распределённой HA-сети, MFA, Minecraft-сессий и всех клиентских платформ остаётся **отдельной обязательной задачей**, которую этот инструмент не закрывает.

Для запуска нужен Linux с Python 3.12+, Docker Engine/Compose, настоящие `.env`, TLS/DNS, сборочные инструменты, достаточное место, реальные PostgreSQL/Redis/S3 для соответствующего стенда, доступ к секретам и отдельный оператор. Стандартные команды управляют действующими данными и могут прерывать обслуживание. **Не запускать их на живых клиентских серверах без согласованного окна.** Работать из корня проверенной ревизии. Перед каждой операцией проверить исходный коммит, SHA-256 и права файлов. В документации используются адреса-примеры — заменить собственными проверенными именами и сертификатами. Не использовать `curl -k`, отключение подписей и заимствованные PASS-отчёты.

## Подготовка

В отдельном приватном каталоге (`0700`) хранить отчёты; операции, запускаемые через `sudo`, пишут отчёты от root, поэтому сбор и сверку выполнять тем же защищённым способом; `.env` и пароль первого администратора должны иметь режим `0600`. Команды выполнять от имени **второго** ОС-пользователя; при `sudo` инструмент читает `SUDO_USER` и отклоняет совпадение с `--primary-operator`. Это минимальная локальная проверка независимости, не криптографическая аттестация человека.

```sh
sudo install -d -m 0700 /var/lib/launcher-acceptance
python3 scripts/operations/independent_accept_04514.py --help
python3 scripts/operations/independent_accept_04514.py install-standard --help
```

### A. Чистая установка 0.45.14 на хосте A

Подготовить `.env` для **0.45.14** по [инструкции установки](installation.md), DNS, TLS, первый администратор и его пароль в отдельном файле. Хост должен быть чистым: старый `.launcher-compose-state.json` препятствует приёмке. Запуск делает **`production-deploy.py compose check` → `compose up` → `first-admin` → фактический `operator_accept live`**. Первичная настройка обязана завершиться действительным входом, повторный вызов первичной настройки не выполняется. Секреты не попадают в отчёт.

```sh
sudo python3 scripts/operations/independent_accept_04514.py install-standard \
  --primary-operator primaryuser --project launcher \
  --env-file /opt/launcher/deploy/production/.env \
  --version 0.45.14 --url https://launcher-a.example.org \
  --email admin@example.org --password-file /etc/launcher/first-admin-password \
  --report /var/lib/launcher-acceptance/install.json
```

После этого **вручную** подтвердить MFA, первый проект и доступ владельца. `PASS` первого этапа означает фактическую начальную загрузку, вход и готовность, но **не MFA**. Парольный файл безопасно удалить согласно локальной политике.

### B. Обновление 0.45.13 → 0.45.14 на существующем Standard-хосте B

Должен работать **именно 0.45.13**. Подготовить два отдельных `.env` с одинаковыми секретами и конфигурацией; разрешено изменить только `LAUNCHER_IMAGE_TAG` (и управление автоматическими миграциями). В целевом `.env` обязательно `LAUNCHER_DATABASE_AUTO_MIGRATE=false`. Обеспечить необходимый исходный код и сборку Docker нового релиза, частный каталог снимков `0700`, окно обслуживания, отсутствие посторонних процессов записи в SQL. Это **только переключение компонентов на новую версию**; при изменениях схемы отдельно использовать [Database Upgrade](upgrades.md). Система сначала собирает новые образы, сохраняет согласованный снимок PostgreSQL/volumes, проверяет неизменность WAL, переключает API/Admin и при ошибке возвращает старые образы. После успеха повторно проверяются снимок, работающий Backend, вход прежнего владельца и чтение заранее существовавшего проекта. При включённом TOTP передайте `--totp-file /etc/launcher/owner-totp-code` (файл `0600` с текущим кодом). Вход, требующий WebAuthn/passkey, нельзя автоматически подменять паролем или объявлять успешным: завершите его вручную и зафиксируйте независимый результат.

```sh
sudo python3 scripts/operations/independent_accept_04514.py upgrade-standard \
  --primary-operator primaryuser --project launcher --confirm launcher \
  --source-env /etc/launcher/standard-04513.env \
  --target-env /etc/launcher/standard-04514.env \
  --from-version 0.45.13 --to-version 0.45.14 \
  --admin-email admin@example.org --admin-password-file /etc/launcher/owner-password \
  --project-id existing-project \
  --snapshot /srv/launcher-backups/acceptance-source \
  --url https://launcher-b.example.org --maintenance-approved \
  --report /var/lib/launcher-acceptance/upgrade.json
```

Снимок создаётся **до** переключения. Его следует перенести на хост C вместе с приватным `upgrade.json` и отдельными **внешними** секретами и TLS-конфигурацией (они не входят в Standard-снимок). Не переносить их по незащищённым каналам. Если source schema изменилась из-за стороннего процесса, прекратить приёмку.

### C. Восстановление исходной 0.45.13 на чистом хосте C

На новом хосте должны быть пустые контейнеры и тома, версии образов **0.45.13**, доступ к тем же данным резервной копии, отдельным секретам и доверенному HTTPS для **нового** хоста. Публичное имя хоста и источник WebAuthn должны относиться к новому тестовому контуру (приложение не должно обращаться к старой серверной части). `--source-receipt` связывает снимок с оригинальным хостом через SHA-256 `manifest.json`. Фактический отпечаток Linux `machine-id` восстановленного хоста должен отличаться от источника. **Не поднимать два пишущих контура с одинаковой идентичностью**.

```sh
sudo python3 scripts/operations/independent_accept_04514.py restore-standard \
  --primary-operator primaryuser --project launcher --confirm launcher \
  --source-receipt /var/lib/launcher-acceptance/upgrade.json \
  --env-file /etc/launcher/standard-restore-04513.env \
  --snapshot /srv/launcher-backups/acceptance-source \
  --admin-email admin@example.org --admin-password-file /etc/launcher/owner-password \
  --project-id existing-project \
  --url https://recovered.example.org --maintenance-approved \
  --report /var/lib/launcher-acceptance/restore.json
```

`restore-fresh` восстанавливает реальный PostgreSQL и тома данных, сверяет содержимое, запускает серверную часть и проверяет `/ready`. Затем выполняются независимая проверка работающих контейнеров и публичного TLS, а также автоматическая проверка входа прежнего владельца и чтения заранее существовавшего проекта. **Обязательно отдельно** проверить чтение сохранённого двоичного объекта: одна проверка работающей системы не подтверждает эти пользовательские действия. Если отказ — целевой контур не объявлять пригодным к эксплуатации.

### D. Failover на изолированном Network-HA стенде D

Отдельный Docker Compose проект с именем `nl-dr-*`, тестовый контейнер объектов MinIO того же формата, изолированный локальный входной HTTPS-прокси и доверенный сертификат. `AWS_ACCESS_KEY_ID` и `AWS_SECRET_ACCESS_KEY` должны соответствовать тестовым учётным данным S3. Требуются **оба API, оба обработчика заданий, PostgreSQL, Redis, MinIO и Nginx**, физически работающие. Запускается **`chaos_0456.py`**: реальные остановки PostgreSQL/Redis/MinIO/API и отключение сети обработчика заданий; контроль подтверждённых PostgreSQL/S3-записей, фактические RTO и canary RPO. Никакой production-проект эта команда не принимает.

```sh
sudo --preserve-env=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY python3 scripts/operations/independent_accept_04514.py failover-network-ha \
  --primary-operator primaryuser --project nl-dr-acceptance --confirm nl-dr-acceptance \
  --env-file /etc/launcher/ha-chaos.env \
  --url https://127.0.0.1/ready --version 0.45.14 \
  --s3-endpoint http://127.0.0.1:19000 --s3-bucket nl-dr-acceptance \
  --report /var/lib/launcher-acceptance/failover.json
```

Результат `rpoSecondsObservedCanaries: 0` относится **только к подтверждённым контрольным данным**, а не ко всем операциям игроков и реальному RPO. На одном Docker-хосте не доказывается переживание отказа физического узла.

### E. Сверка четырёх защищённых отчётов

Скопировать по защищённому каналу отчёты в отдельный каталог приёмки с правами `0600`; `upgrade.json` должен сохранить **точные байты**, по которым хост C строил свой `restore.json`. Проверка подтверждает различие идентификаторов машин (machine-id) источника и восстановленного узла, связность SHA-256 и единый локальный аккаунт второго оператора. Не выдаёт самоподписанный сертификат независимого аудитора.

```sh
sudo python3 scripts/operations/independent_accept_04514.py verify-receipts \
  --primary-operator primaryuser \
  --install-receipt /var/lib/launcher-acceptance/install.json \
  --upgrade-receipt /var/lib/launcher-acceptance/upgrade.json \
  --restore-receipt /var/lib/launcher-acceptance/restore.json \
  --failover-receipt /var/lib/launcher-acceptance/failover.json \
  --report /var/lib/launcher-acceptance/verified.json
```

## Признаки реального успеха

В каждом этапе отчёт `status: passed` создаётся только после успешного исполнения целевого инструмента и проверки результата. Ошибки не создают PASS-файл; журнал чужих систем не импортируется как подтверждение; старый отчёт не перезаписывается. Все отчёты имеют mode 0600 и требуют приватного каталога. Скрипт **не** подделывает отсутствующие результаты, не перезаписывает БД вручную и не обходит реальные подписи release/updater.

**Ограничение 0.45.14:** наличие кода, локальные модульные тесты и подготовленное пошаговое руководство не равны выполнению этих шагов вторым оператором на реальных хостах. `verify-receipts` проверяет согласованность локальных JSON, но они не подписаны независимой доверенной стороной; доказывать личность оператора, аппаратную независимость и официальные значения RPO/RTO промышленной среды необходимо отдельной процедурой. Критерии 0.46.0 и оставшиеся ручные действия см. в [общей ведомости](operator-checklist.md).
