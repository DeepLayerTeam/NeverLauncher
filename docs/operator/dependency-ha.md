# Launcher 0.51.3 — высокая доступность зависимостей и переключение входящего трафика

## Что действительно работает

Два **отдельных узла балансировщика** запускают HAProxy и Keepalived, один
владеет публичным и зависимостным VRRP VIP. В случае потери активного
HAProxy VIP должен перейти второму узлу, который уже проверяет состояние зависимых сервисов.

Четыре L4-маршрута TCP/TLS (без TLS-терминации и без пересоздания неидемпотентных запросов):

| VIP | Порт | Реальный критерий выбора |
|---|---|---|
| Публичный | 443 | HTTPS `GET /ready` на входящем узле API через проверяемый TLS; 2 узла |
| Зависимостей | 5432 | Patroni `GET /primary` на каждом PostgreSQL узле; ровно один действующий процесс записи |
| Зависимостей | 6380 (пример) | Redis TLS, `AUTH` выделенного health-пользователя, затем `INFO replication` с `role:master` |
| Зависимостей | 443 | HTTPS проверка здоровья S3 gateway с подтверждением quorum, затем **подписанный** межшлюзовый PUT/GET/DELETE тест |

Это **исполняемое HA-переключение маршрута**, а не собственная реализация
репликации PostgreSQL, Redis или объектов. Для PostgreSQL обязательно
отдельно настроить рабочие ведущий узел и реплики Patroni и отказоустойчивый DCS
с кворумом и защитой от устаревшего владельца; для Redis — Redis Sentinel/поддерживаемый кластер с
безопасным назначением нового ведущего узла; для S3 — одно распределённое реплицируемое пространство имён
с готовыми шлюзами, подтверждёнными согласованностью и сохранностью данных. Без них
добавление HAProxy создаёт только новые точки отказа. Не использовать
несвязанные S3 buckets/кластеры как взаимозаменяемые конечные точки.

**Предупреждение:** VRRP сам по себе не исключает конфликт VIP при
сетевом разделении. 0.51.4 отдельно вводит проверенную защиту при сетевом разделении;
текущий выпуск не гарантирует отсутствие двух одновременно активных ведущих узлов в произвольной сети.

## Сетевой/эксплуатационный контракт

1. Два независимых узла Linux с HAProxy/Keepalived; совместимый HAProxy 2.8+,
   Keepalived, `iproute2` и systemd. Отдельные узлы API и обработчиков заданий из 0.51.2.
   Два VIP в **одной L2 подсети** с адресами обоих LB. Настроить межсетевой экран:
   VRRP unicast между LB, клиентский порт 443 на публичном VIP, трафик API и обработчиков заданий
   к PostgreSQL 5432, Redis TLS 6380 и S3 HTTPS 443 на VIP зависимостей.
   Только балансировщикам доступен порт REST для проверки работоспособности Patroni (обычно 8008);
   его не публиковать в интернет. Ограничить и аутентифицировать
   административный SSH. Не соединять независимые VLAN только через VRRP.
2. DNS имена `launcher.example`, `postgres-ha.internal`,
   `redis-ha.internal`, `s3-ha.internal` указывают на нужные VIP. Сертификат
   **каждого** вышестоящего сервиса Redis/S3/HTTPS обязан содержать его
   стабильное DNS имя. PostgreSQL должен предъявлять сертификат, который
   проверяется libpq по `postgres-ha.internal` при `sslmode=verify-full`.
   Прокси не расшифровывает трафик клиента.
3. На PostgreSQL узлах Patroni `/primary` возвращает HTTP 200 **только**
   на узле с действующей блокировкой ведущего узла DCS; REST API защищён отдельной
   управляющей сетью. Синхронное подтверждение WAL и допустимое RPO
   задаются Patroni/PostgreSQL; прокси не может сделать асинхронную репликацию
   без потерь. Потеря quorum должна блокировать опасные записи.
4. Redis TLS и сертификаты на каждом сервере. Выделенный пользователь ACL для
   проверок работоспособности имеет только разрешение `INFO replication` и не имеет
   доступа к произвольным ключам. Пароль находится в отдельном `0600`
   файле, а не в Git, `.env` или отчёте; в сгенерированном HAProxy
   конфиге AUTH команда записана в RESP hex, что **не является шифрованием**:
   конфиг строго `0600`, доступ root/ограниченного администратора.
   ServerBridge и механизм ограничения частоты запросов должны блокировать операции при недоступном
   primary. Нельзя без дополнительного протокола гарантировать сохранность
   аренды блокировки Redis через потерю неподтверждённой репликации (0.51.4).
5. Конечная точка S3 использует запросы с путевыми адресами к единому пространству объектов.
   S3 health URL (`/minio/health/cluster` для совместимых шлюзов MinIO)
   должен подтверждать наличие кворума, а не только готовность HTTP-сервера.
   Выделить отдельные короткоживущие ключи для активной проверки только
   под `launcher-ha-probe-0513/*`: `PutObject`, `GetObject`, `DeleteObject`.
   Каждый `verify` выполняет подпись AWS SigV4, прямое TLS/SNI подключение
   к каждому работающему шлюзу и побайтовое сравнение ответов между шлюзами.
   Если данные не совпадают, статус FAIL независимо от результата HTTP-проверки работоспособности.
6. Установить актуальные проверенные пакеты из доверенного репозитория ОС,
   не отключать проверку TLS/CA. Контролировать число ведущих узлов (должно быть 1),
   число входящих узлов/шлюзов (не меньше 2 в стабильном состоянии), состояние
   VRRP и результаты реальных приложения /ready/growth.

## Установка на ОБОИХ балансировщиках

Пример: публичный VIP `10.20.0.100`, VIP зависимостей `10.20.0.101`,
первый LB `10.20.0.11` (priority 150), второй `10.20.0.12` (priority 100).
Секреты, сертификаты и настоящие IP не поставляются в репозитории.

```bash
sudo install -d -m 0700 /etc/launcher/secrets
sudo install -m 0600 deploy/production/dependency-ha-0513.example.env /etc/launcher/ha-0513.env
sudo install -m 0600 /dev/null /etc/launcher/secrets/redis-ha-health-password
sudo install -m 0600 /dev/null /etc/launcher/secrets/s3-ha-probe-access-key
sudo install -m 0600 /dev/null /etc/launcher/secrets/s3-ha-probe-secret-key
# Безопасно заполнить секреты напрямую на хосте (НЕ в истории shell).
# Заполнить фактические IP/DNS и CA, на LB-2 поменять LOCAL/PEER и PRIORITY.
sudo install -d -m 0700 /var/lib/launcher/ha-0513-render
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py render \
  --env-file /etc/launcher/ha-0513.env \
  --output-dir /var/lib/launcher/ha-0513-render
sudo install -m 0600 /var/lib/launcher/ha-0513-render/haproxy.launcher-0513.cfg /etc/haproxy/haproxy.cfg
sudo install -m 0644 /var/lib/launcher/ha-0513-render/keepalived.launcher-0513.conf /etc/keepalived/keepalived.conf
sudo install -m 0644 /var/lib/launcher/ha-0513-render/99-launcher-ha-nonlocal-bind.conf /etc/sysctl.d/99-launcher-ha-nonlocal-bind.conf
sudo sysctl --system
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py check \
  --haproxy-config /etc/haproxy/haproxy.cfg \
  --output /var/lib/launcher/haproxy-check-0513.json
sudo systemctl enable --now haproxy keepalived
```

**Перед установкой** создать резервные копии действующих конфигураций;
эти команды *заменяют* `/etc/haproxy/haproxy.cfg` и
`/etc/keepalived/keepalived.conf`, поэтому не применять поверх другого
продукта без согласованного обслуживания. `render` никогда не перезаписывает
существующий файл. HAProxy на резервном узле должен иметь
`net.ipv4.ip_nonlocal_bind=1`, иначе он не сможет занять VIP до назначения.
Если система имеет другой путь бинарника `systemctl`, адаптировать
проверку Keepalived и валидировать её вручную до ввода.

В DNS/LB-конфигурации клиентов 0.51.2 задать общие endpoint-адреса:

```dotenv
LAUNCHER_DATABASE_DSN=postgres://launcher:SECRET@postgres-ha.internal:5432/launcher?sslmode=verify-full
LAUNCHER_REDIS_URL=rediss://:SECRET@redis-ha.internal:6380/0
LAUNCHER_STORAGE_S3_ENDPOINT=https://s3-ha.internal
LAUNCHER_PUBLIC_URL=https://launcher.example
```

Запускать только с реальным TLS/CA и одинаковыми бакетом S3, настройками авторизации и
ключами выпуска на всех узлах API и рабочих процессов. Код 0.51.2 по-прежнему запрещает локальные
PostgreSQL/Redis и ручной запуск необслуживаемых образов.

## Живое подтверждение

На LB с работающим HAProxy (отчёты строго приватны, без секретов):

```bash
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py verify \
  --env-file /etc/launcher/ha-0513.env \
  --edge-url https://launcher.example \
  --node a=operator@api-a.internal --node b=operator@api-b.internal \
  --output /var/lib/launcher/ha-0513-baseline.json
```

`verify` запрашивает действующий сокет статистики HAProxy в Unix, **запрещает два
одновременно доступных writer**, требует 2 ingress+2 S3 gateways, реальный
доступ к /ready, строгие ключи хоста SSH и пробы приложения через его уже
существующий `launcher-api diagnose growth`: изоляция PostgreSQL, аренда блокировки Redis
и S3 read/write/delete. Отдельно выполняет AWS SigV4 PUT→GET между
различными прямыми S3 шлюзами, с TLS hostname verification. Отчёт не
содержит DSN/секреты; отсутствие права или сервера — ошибка, не PASS.

## Испытания с имитацией отказов (ТОЛЬКО разрешённая тестовая среда)

Пример: отключение **текущего** процесса записи PostgreSQL `pg-a`, если HAProxy stats до
испытания показывает `pg-a` UP. `--target` — независимо сверенный SSH
хост именно этого сервера. SSH должен разрешать *только* необходимые
`sudo -n systemctl stop/start patroni`, аналогично для `redis-server`
или `minio`. Программа проверяет базовое здоровье, останавливает сервис,
ждёт появления другого primary/gateway, проверяет фактическую доступность API и рабочих процессов
работу и signed S3 roundtrip, затем всегда пытается перезапустить сервис.
После перезапуска снова ждёт базового здоровья.

```bash
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py drill \
  --env-file /etc/launcher/ha-0513.env --edge-url https://launcher.example \
  --node a=operator@api-a.internal --node b=operator@api-b.internal \
  --service patroni --backend-server pg-a --target operator@pg-a.internal \
  --allow-disruption --deadline 120 \
  --output /var/lib/launcher/ha-0513-pg-a.json
```

Для Redis сменить на `--service redis-server --backend-server redis-a`,
для S3 `--service minio --backend-server s3-a`. Служба должна иметь эти
действительные имена служб systemd; для управляемых облачных сервисов
использовать API провайдера для моделирования отказов и отдельно приложить подтверждения.
Тест остановки Redis требует наличия Sentinel/quorum и работоспособного механизма назначения нового ведущего узла. При непредвиденной ошибке SSH система может быть недоступна
даже после попытки восстановления: необходим резервный административный доступ вне основного канала.

Для активного LB — **отдельный** сценарий, запускать НА РЕЗЕРВНОМ LB.
Проверяется факт, что на исходном удалённом балансировщике был публичный VIP, на резервном
его не было. Затем отключается HAProxy на активном, проверяется появление
**обоих VIP** на резервном, доступность публичного HTTPS `/ready`,
маршрутов dependencies и дополнительные проверки роста нагрузки API и рабочих процессов.

```bash
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py edge-drill \
  --env-file /etc/launcher/ha-0513.env --edge-url https://launcher.example \
  --node a=operator@api-a.internal --node b=operator@api-b.internal \
  --target operator@lb-active.internal --allow-disruption \
  --output /var/lib/launcher/ha-0513-lb.json
```

**Фактические результаты**: измерить RTO/RPO для PostgreSQL, Redis,
S3 и ingress отдельно; подтвердить состояние миров, UUID, identities,
реплик и сохраняемых заданий; сверить количество подтверждённых записей до/после.
Механизм outage probe не утверждает сохранность всех данных по одному контрольному объекту,
и не заменяет проверку power-off, разделения сети, разделения узлов Redis при аренде блокировки или
выполнения JVM и игрового процесса. Разделение кластера на независимые части и изоляция прежнего владельца относятся к 0.51.4,
Поэтапные обновления N/N−1 — к 0.51.6/0.51.7, восстановление — к 0.51.8/0.51.9.

## Правила релиза

- **Никогда не объявлять GA PASS по локальным unit tests или `haproxy -c`.**
  Рабочие скрипты и безопасная конфигурация поставляются как код;
  реальное переключение проверяется только на независимых hosts и signed
  receipts точных конечных файлов.
- Два одновременно доступных процесса записи PostgreSQL или Redis — FAIL (потенциальный
  split-brain); один доступный gateway S3 позволяет продолжать безопасные
  операции после отказа, но не проходит требование базовой избыточности.
- Два active S3 gateways без общей реплицируемой базы не считаются HA.
- Ошибки сертификатов, ACL, проверки готовности API или неверное содержимое объекта
  блокируют выпуск; TLS verification нельзя отключать ради PASS.
