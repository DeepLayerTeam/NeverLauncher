# NeverLauncher 0.51.1 — инвентаризация HA и базовая оценка доменов отказа

## Реальный инструмент и назначение

`ha_inventory_0511.py` выполняет инвентаризацию **фактически запущенных** Docker-контейнеров (Docker API через `docker ps/inspect`), health/readiness каждого API/worker и реальные зависимости через штатное `launcher-api diagnose growth`. При наличии контейнеров PostgreSQL и Redis он выполняет запросы только для чтения к работающим PostgreSQL и Redis и сохраняет измеренные задержки `/ready`. Никаких изменений в пользовательской БД или конфигурации аудит не вносит; существующий `diagnose growth` кратковременно создаёт и удаляет специально именованные тестовые Redis-lease и S3-объект.

Реализация проверяет фактическую `LAUNCHER_PROCESS_ROLE`, постоянную `LAUNCHER_REPLICA_ID`, запрет авто-миграции в работающих репликах, PostgreSQL/S3/fencing/rate-limit policy, запущенность и Docker health; при подозрительных настройках или невозможности проверки ставит `RISK` либо `UNVERIFIED`, **никогда не фиктивный PASS**. Отдельно отслеживаются локальные mountpoints: storage, backups, factory, coordinator, extensions. Указано, что их роль в сохранности распределённого состояния должна проверяться отдельно. Анализ исходников фиксирует локальные поля `RuntimeState` и загрузку persistence snapshot при старте; он **не** подтверждает согласованность MFA/passkeys между API-репликами.

Инструмент не извлекает ENV целиком, `.env`, ключи, токены, SQL-данные, журналы запросов или содержимое томов. В отчёте остаются имена контейнеров/реплик, имена Docker volumes, роли, endpoint hostnames **без** секретов и SHA бинарников/исходников. Храните JSON как приватные операторские метаданные. Новый файл отчёта создаётся атомарно с `0600` без перезаписи. Требуется право доступа к Docker Engine, поэтому запускайте инструмент только в доверенном административном контуре.

## На одном Docker-хосте

```bash
cd /opt/launcher  # дерево NeverLauncher 0.51.1, где находится scripts/operations/
python3 scripts/operations/ha_inventory_0511.py node \
  --project launcher --samples 5 \
  --source-root /opt/launcher \
  --output /var/tmp/ha-inventory-node-a.json
```

Код завершения: `0` — сбор выполнен без **локально** обнаруженных ошибок (это НЕ HA GA); `3` — отчёт записан, найдены реальные риски; `2` — аудит не удалось выполнить полностью, нельзя считать объект проверенным. Не переиспользуйте существующий путь отчёта: каждая проверка создаёт новый файл.

## Несколько Docker-хостов

На каждом хосте должны находиться одинаковые версии инструмента и доверенное дерево проекта. SSH доступ — ключевой, `BatchMode`, `StrictHostKeyChecking=yes`; интерактивное подтверждение host key и парольная аутентификация намеренно не используются. Запускающий узел обязан иметь Docker; удалённые `operator@host` получают локальные сведения с **их собственных** Docker Engines.

```bash
python3 scripts/operations/ha_inventory_0511.py cluster \
  --project launcher-prod \
  --node a=local \
  --node b=operator@host-b.example.net \
  --remote-script /opt/launcher/scripts/operations/ha_inventory_0511.py \
  --edge-url https://launcher.example.net/ready \
  --samples 5 \
  --source-root /opt/launcher \
  --output /var/tmp/ha-inventory-cluster-20261103.json
```

`--skip-growth` пригоден только при диагностике проблем с доступами: он **не** подменяет недостающие реальные проверки. Никакие секреты не передаются по SSH как аргументы CLI. На удалённом хосте контейнер получает свои уже настроенные credentials. Docker Engine ID и `/etc/machine-id` в отчёте представлены короткими SHA-256 fingerprints. Совпадение host IDs означает риск общего failure domain, но различие host IDs **не доказывает** физическую независимость: две VM могут быть на одном гипервизоре, SAN или в одной стойке. Требуется независимая проверка физической топологии.

Внутренние readiness-пробы выполняются внутри каждого контейнера (`wget` к loopback `/ready`), а внешний HTTPS endpoint проверяется с TLS-проверкой и запретом редиректов; фиксируются реальные `p50Ms`/`p95Ms`. Пробы по умолчанию не выполняют пользовательских mutations, не создают публикаций или ServerBridge-команд. Для PostgreSQL/Redis при локальном размещении показывается информация только для чтения о репликации, а не обещание автоматического failover. При вынесенных зависимостях и внешних auth/DNS/secret providers статус `UNVERIFIED` до отдельных операторских тестов. Поля `multiHostFailoverCertified: false` и `requiresIndependentFaultTest` выставляются намеренно: 0.51.1 не является 0.52.0.

## Обнаруженные в архиве 0.51.0 проблемы

1. `deploy/production/docker-compose.network-ha.yml` определяет два API и два worker, но все сервисы одного `docker compose` остаются в одном failure domain при запуске на одном Docker-хосте. `docker-compose.yml` содержит по одному локальному PostgreSQL, Redis, Admin и Nginx. Не обозначайте эту инсталляцию как выдерживающую потерю хоста.
2. `services/api/internal/httpapi/runtime_state.go`: локальные объекты `AuthSessions`, `Security`, `Passkeys`, `ServerBridge`, `Maintenance`, `PackageMutation`, `BackendLifecycle0289`. Некоторые компоненты используют собственные PostgreSQL persistent stores, однако снимки из `persistence.go` загружаются на старте. Для каждого изменяемого поля требуется фактический cross-replica write/read и read-after-restart, иначе общая БД ещё не доказывает видимость изменения второму API.
3. `component_upgrade_0458.py` выполняет переключение с остановкой; совместимость схем N/N−1 и обновление без одновременной остановки ещё не доказаны.
4. `growth.go` проверяет PostgreSQL advisory lock, Redis lease и S3 cross-client roundtrip **в момент вызова**, но это не тест split-brain при partition, смены primary или потери всех сервисов одного хоста.
5. `ServerBridge` worlds и управляемые Minecraft-процессы живут вне исследуемого API Compose; их единственного владельца, snapshots и восстановления этот аудит не проверяет.
6. До 0.51.1 при отсутствии `LAUNCHER_REPLICA_ID` мог использоваться сгенерированный от hostname/PID идентификатор. Теперь Network-HA запуск не принимает пустой или некорректный ID; идентификатор обязан быть стабилен между restart и уникален для реплики.

## Требуемая следующая проверка

После инвентаризации: подтвердить разные физические failure domains для API, worker и ingress; проверить конфигурацию и управление PostgreSQL/Redis/S3, внешними секретами и DNS; выполнить write→read на *другом* API для сессий, MFA, passkeys, профилей и ServerBridge; согласовать single-writer для миров; задать partition rule и fencing/epoch для опасных операций. Только затем переходить к фактическому развёртыванию 0.51.2 и fault-injection 0.51.4. Не считать `OBSERVED` сертификатом `PASS` при аварии.

## Тестирование этого изменения

```bash
python3 -m unittest discover -s scripts/operations -p 'test_ha_inventory_0511.py' -v
cd services/api && go test ./internal/deployment -run 'TestAutoDetectStandardAndNetworkHA|TestExplicitModeRejectsUnsafeCombinations' -count=1
```

В текущем рабочем окружении нет Docker Engine и установлен Go 1.23.2 при требовании исходников Go 1.27.3, поэтому **live Docker/PG/Redis/S3/SSH стенд и Go suite не выполнялись**. Непроверенное остаётся блокером для GA, а не положительным результатом.
