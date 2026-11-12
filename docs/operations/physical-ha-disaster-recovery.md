# Launcher 0.52.10 — эксплуатация физического HA и аварийного восстановления

**Рабочие промышленные пути выполнения, но не заявление о завершённой приёмке.** Эти команды намеренно разрушают работающее состояние. Используйте изолированный аппаратный стенд под независимым управлением без действующих клиентов. CI-тесты 0.52.10 — локальные регрессии; до принятия любой квитанции физической приёмки на целевой инфраструктуре необходимо наблюдать отключение физических хостов, изоляцию маршрутизируемой сети, повышение PostgreSQL/Redis/S3, доставку оповещений и восстановленный игровой процесс Minecraft.

## Разделение ответственности

Наблюдатель — Linux-хост **вне доменов отказа** HA. Два или более разных физических узла API и рабочих процессов используют настоящее развёртывание `multi_host_0512.py`, неизменяемые образы, TLS-балансировщик и общие PostgreSQL/Redis/S3. Отдельная управляющая сеть BMC Redfish должна сохранять доступность при потере прикладного хоста. Целью может быть только лабораторная машина, чей **настоящий Redfish SerialNumber** совпадает с `--expected-serial`. Для HTTPS BMC нужен настоящий доверенный CA-файл; запрещены `-k`, скрытые перенаправления, пароль в URL и исходные учётные данные в файлах квитанций. Используйте отдельные ограниченные Redfish API-токены для каждого хоста в закрытых файлах 0600. BMC-аккаунт должен иметь право выполнить `ForceOff` и `On` на одобренной системе. До теста подтвердите, что этот BMC действительно поддерживает такие операции `ResetType`.

Наблюдателю нужны закреплённые SSH-ключи хостов и ограниченные права sudo только на одобренных HA-узлах и выделенном маршрутизаторе. Заранее создайте каталог 0700 под управлением наблюдателя. Перед удалённым воздействием каждый физический сбой записывает эксклюзивный журнал `--state` с fsync. Незавершённый или неопределённый сбой оставляет журнал; до следующего учения требуется `heal`. Не удаляйте журнал ради обхода проверки. Все отчёты имеют права 0600 и записываются ровно один раз.

### Реальные уведомления зависимых систем

Поставляемый `scripts/operations/alert_receiver_05210.py` — действующий получатель webhook Alertmanager: `POST /webhook` аутентифицируется отдельным токеном доступа Bearer, проверяет настоящее сработавшее событие и отпечаток, совместимый с SHA, и атомарно сохраняет квитанцию через fsync в `latest.json`. `GET /events/latest` требует **другой** токен читателя. Служба слушает **только 127.0.0.1**. Разместите на независимом хосте уведомлений отдельный управляемый обратный прокси-сервер HTTPS с проверенным сертификатом, который перенаправляет оба маршрута на localhost. Оба файла токенов должны быть обычными, без символьных ссылок, закрытыми, с правами 0600. Каталог получателя — 0700 и принадлежит процессу. Пример запуска:

```sh
python3 scripts/operations/alert_receiver_05210.py \
  --directory /srv/launcher-alert-receipts --port 18871 \
  --expected-alert LauncherHostIngressDown \
  --webhook-token-file /etc/launcher/alerts-webhook.token \
  --reader-token-file /etc/launcher/alerts-observer.token
```

Настройте действующую маршрутизацию Alertmanager для доставки нужного события на `https://notifications.example.net/webhook` с `http_config.authorization.credentials_file`, где лежит Bearer-токен webhook, **не** токен читателя. Защитите HTTPS и не открывайте loopback-получатель напрямую. Физический исполнитель независимо опрашивает **и** Alertmanager `/api/v2/alerts`, **и** `/events/latest` внешнего хоста уведомлений, сопоставляя имя события, отпечаток и метки времени **после** начала сбоя. Уже существующее состояние Alertmanager без подтверждения доставки конечному получателю означает BLOCKED, а не PASS. Исправный кластер без настоящего оповещения также даёт BLOCKED. Выбирайте `--alert-name` из развёрнутых правил Prometheus для нужного отказа (например, `LauncherHostIngressDown`).

## 1. Потеря питания физического сервера: BMC ForceOff и восстановление

Убедитесь, что наблюдатель по собственной сети управления по-прежнему видит каждый сервер и публичный входной HTTPS-шлюз. На независимом наблюдателе с закрытыми файлами в `/secure/physical-05210` выполните:

```sh
python3 scripts/operations/physical_ha_dr_05210.py host \
  --node a=ops@node-a.example.net --node b=ops@node-b.example.net \
  --victim a --project launcher \
  --directory /opt/launcher/deploy/production \
  --edge-url https://launcher.example.net/ready \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name LauncherHostIngressDown \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/power-a.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

Команда выполняет **настоящее переключение питания Redfish**, наблюдает BMC `Off` и потерю SSH к **конкретному** хосту, проверяет независимо идентифицированные оставшиеся узлы и многократные обращения к публичному входному HTTPS-шлюзу, подтверждает внешнюю доставку оповещения, запрашивает BMC `On` даже при ошибке наблюдения и затем проверяет восстановление всего кластера. Обычная успешная команда `systemctl stop` или `docker stop` не удовлетворяет сценарию. Ошибка восстановления BMC или отсутствие конечной проверки исходного состояния оставляют журнал на месте.

## 2. Разделение сети в *маршрутизируемой* физической сети приложения

Устанавливайте `deploy/production/physical-partition-05210.nft` **только** на выделенный L3 Linux-маршрутизатор между целевым настоящим узлом и остальными узлами/зависимостями. Таблица `inet launcher_partition_05210` содержит отдельную цепочку пересылки и динамический набор IPv4 с истечением срока; никакой узел не блокируется, пока в набор не добавлен конкретный закрытый адрес. Проверьте правила пересылки источника и назначения, а также timeout ядра для набора. Убедитесь, что внешняя управляющая/BMC-сеть и наблюдатель **не** проходят через этот firewall. При общем L2-сегменте метод не разделяет трафик соседей через один коммутатор; проверки TCP между участниками откажут в PASS. Метод не утверждает проверку произвольного физического обрыва оптоволокна/кабеля.

```sh
# Запустите однократно на выделенном маршрутизаторе после оценки точных последствий:
sudo nft -f /opt/launcher/deploy/production/physical-partition-05210.nft
# Затем на независимом наблюдателе:
python3 scripts/operations/physical_ha_dr_05210.py partition \
  --node a=ops@node-a.example.net --node b=ops@node-b.example.net \
  --victim a --victim-ip 10.14.0.11 --victim-port 443 \
  --router ops@router.example.net --ttl 190 --timeout 120 \
  --project launcher --directory /opt/launcher/deploy/production \
  --edge-url https://launcher.example.net/ready \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name LauncherHostIngressDown \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/partition-a.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

Проверяющий требует: TCP-связь от каждого оставшегося узла к настоящему прикладному порту жертвы **до** отказа; её отсутствие, пока BMC всё ещё сообщает `On`, а **управляющий SSH остаётся доступен**; исправность оставшихся служб и ingress; внешнюю доставку оповещения; восстановление TCP между узлами и всех процессов кластера. Срок действия в ядре удаляет оставшийся элемент набора при гибели наблюдателя. Средство также удаляет его при обычном выходе. TTL короче требуемого окна наблюдения отклоняется. Одна потеря управляющего SSH **не** считается свидетельством физического разделения сети.

## 3. Переключение зависимостей PostgreSQL/Redis/S3 при отказе

Контроллер 0.52.10 напрямую вызывает существующий `dependency_ha_0513.py`. Для PostgreSQL/Redis он теперь запрещает остановку реплики и требует нарушить работу **действующего основного узла**, после чего наблюдать другой активный основной узел. Проверяется, что одобренная SSH-цель владеет заданным внутренним IPv4 на настоящем сетевом интерфейсе, даже если управляющий SSH использует другой IP. Для S3 выполняются подписанные операции PUT и обратное чтение через оставшиеся шлюзы средствами промышленной проверки работоспособности. Контроллер заранее планирует удалённый временный юнит `systemd-run` для перезапуска нарушенной службы, даже если процесс наблюдателя будет убит, пишет журнал восстановления и проверяет как переключение при отказе, так и восстановление избыточности. Требуются настоящие кластеры Patroni/Redis/S3 и ограниченные права суперпользователя, а не замена Compose.

```sh
python3 scripts/operations/physical_ha_dr_05210.py dependency \
  --service patroni --backend-server pg-primary-a --target ops@pg-node-a.example.net \
  --ha-env-file /etc/launcher/ha-0513.env \
  --ha-socket /run/haproxy/launcher-ha.sock \
  --edge-url https://launcher.example.net/ready \
  --alertmanager-url https://alerts.example.net \
  --delivery-url https://notifications.example.net/events/latest \
  --delivery-token-file /secure/physical-05210/alerts-reader.token \
  --alert-name LauncherBackendNotReady \
  --state /secure/physical-05210/active.state.json \
  --report /secure/physical-05210/postgres-failover.report.json \
  --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE
```

Для Redis запускайте с `--service redis-server`, а для S3-шлюза — с `--service minio`, указав настоящую идентичность Backend и соответствующую SSH-цель. Имя Backend должно присутствовать в инвентаре настроенного HAProxy. Если служба или кворум остаётся неисправным, журнал восстановления зависимости сохраняется; после исправления кластера используйте проверенный `heal --heal-mode dependency`. Успешный healthcheck одного провайдера не является полной гарантией RPO реплицированного хранилища. Согласуйте подтверждённые транзакции PostgreSQL, объекты S3 и миры отдельно существующими средствами согласованного резервного копирования и DR.

## 4. Восстановление остановленного мира Minecraft с побайтовой проверкой на новом игровом узле

Сначала создайте резервную копию промышленного мира в **подтверждённо остановленном** состоянии штатными инструментами ServerBridge/DR. Восстановите WAL PostgreSQL, S3, защищённые идентичности, права и состояние расширений через `cross_host_recovery_0519.py prepare`, `replay-postgres`, `admit`; отдельно проверьте RTO от инцидента до готовности, выборочный RPO аудита и переключение источника. **Старый физический Minecraft-сервер обязан оставаться в состоянии BMC `Off`**, чтобы исключить двух писателей мира. Запускайте режим `world` на восстановленном игровом хосте с *новым несуществующим каталогом назначения*, закрытым файлом пароля RCON, проверенными исполняемыми скриптами запуска/остановки сервера (абсолютные пути, а не команды shell) и действительным лицензированным игроком, который подключится во время проверки:

```sh
python3 scripts/operations/physical_ha_dr_05210.py world \
  --world-backup /srv/recovery/worlds/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --world-destination /srv/recovered-game/instance-1 \
  --game-start /usr/local/sbin/start-recovered-vanilla \
  --game-stop /usr/local/sbin/stop-recovered-vanilla \
  --game-config /secure/physical-05210/recovered-game.json \
  --rcon-password-file /secure/physical-05210/rcon.token \
  --expected-player VerifiedPlayer \
  --marker-xyz '0 64 0' --marker-block minecraft:diamond_block \
  --redfish-url https://old-game-bmc.example.net/redfish/v1/Systems/1 \
  --expected-serial OLD-GAME-BMC-SERIAL \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/old-game-bmc.token \
  --source-fenced --allow-disruption I-ACCEPT-PHYSICAL-OUTAGE \
  --report /secure/physical-05210/world-restore.report.json
```

Закрытый JSON конфигурации игры содержит `serverDir` (точный новый восстановленный каталог), `minecraftVersion` (`1.21.1` для этой конкретной проверки Vanilla), `minecraftPort` и `rconPort`. Скрипты обязаны управлять **настоящей восстановленной JVM**; скрипт запуска возвращает управление после создания игрового процесса, а не после его завершения. В целевом мире должна быть метка блока, созданная до резервного копирования; принимается только реально наблюдаемый ответ RCON `execute if block ... run say ...` с точной меткой. Проверяющий копирует и повторно хеширует каждый файл мира через `dr_03512.restore_world_backup`, проверяет действующий статус Minecraft, присутствие игрока, увеличение игровых тиков и содержимое метки, затем вызывает настоящее действие остановки сервера. Простая копия или экран меню Minecraft не проходят этап восстановления. **Проверяется один мир и один реальный игрок, а не сохранность всех подтверждённых записей всех миров.**

## Восстановление после прерванного испытания сбоя

```sh
python3 scripts/operations/physical_ha_dr_05210.py heal \
  --heal-mode host --victim a \
  --redfish-url https://bmc-a.example.net/redfish/v1/Systems/1 \
  --expected-serial REAL-BMC-SERIAL-A \
  --bmc-ca /secure/physical-05210/bmc-ca.pem \
  --bmc-token-file /secure/physical-05210/bmc.token \
  --state /secure/physical-05210/active.state.json
```

Для сетевой изоляции вместо этого передайте `--heal-mode partition`, `--router`, `--victim-ip`, `--victim-port` и исходные два аргумента `--node label=target`, а применимые параметры настоящего BMC сохраните. Для нарушенной зависимости передайте `--heal-mode dependency --target ... --backend-server ... --service ... --ha-env-file ... --ha-socket ... --edge-url ...`. `heal` удаляет журнал только после настоящего независимого физического/сервисного восстановления и **не** выдаёт сертификат GA.

## CI и границы версии 0.53.0

Новый `.github/workflows/physical-ha-dr-05210.yml` выполняет локальные отрицательные тесты без оборудования в обычном CI. Его разрушающее задание доступно только через явный `workflow_dispatch`, защищённую среду `physical-ha-lab` и отдельно помеченный self-hosted аппаратный исполнитель; секреты передаются через переменные защищённой среды и не фиксируются в репозитории. Реальный исполнитель завершается ненулевым кодом при отсутствии оборудования или оповещений, отказе кворума, отсутствующей метке/игроке или прерванном восстановлении; он никогда не создаёт поддельные квитанции ради зелёного CI.

Версия 0.52.10 содержит **работающий код физического управления, безопасности, живых проверок и восстановления миров**, но в текущем исходном архиве нет настоящих BMC, выделенного маршрутизатора, физического кворума зависимостей, реального игрового хоста, подписанных окончательных установщиков или независимых внешних квитанций инцидента. Всё это необходимо выполнить до заявления о завершённой физической HA GA-приёмке 0.52.10. Отдельная полная матрица 0.53.0 и независимая сертификация окончательных байтов остаются **BLOCKED**. JSON-квитанция исходников — лишь наблюдение, которое затем нужно независимо подписать и привязать к хешам окончательного выпуска существующими средствами приёмки.
