# NeverLauncher 0.51.3 — высокая доступность зависимостей и переключение входящего трафика

## Что действительно работает

Два **отдельных узла балансировщика** запускают HAProxy и Keepalived, один
владеет публичным и зависимостным VRRP VIP. В случае потери активного
HAProxy VIP должен перейти второму узлу, который уже проверяет upstream.

Четыре L4-маршрута TCP/TLS (без TLS-терминации и без пересоздания неидемпотентных запросов):

| VIP | Порт | Реальный критерий выбора |
|---|---|---|
| Публичный | 443 | HTTPS `GET /ready` на API ingress через проверяемый TLS; 2 узла |
| Зависимостей | 5432 | Patroni `GET /primary` на каждом PostgreSQL узле; ровно один действующий writer |
| Зависимостей | 6380 (пример) | Redis TLS, `AUTH` выделенного health-пользователя, затем `INFO replication` с `role:master` |
| Зависимостей | 443 | HTTPS проверка здоровья S3 gateway с подтверждением quorum, затем **подписанный** межшлюзовый PUT/GET/DELETE тест |

Это **исполняемое HA-переключение маршрута**, а не собственная реализация
репликации PostgreSQL, Redis или объектов. Для PostgreSQL обязательно
отдельно настроить рабочие Patroni primary/replicas и отказоустойчивый DCS
с quorum/fencing; для Redis — Redis Sentinel/поддерживаемый кластер с
безопасным promotion; для S3 — одно распределённое реплицируемое namespace
с готовыми gateway, подтверждённой consistency и durability. Без них
добавление HAProxy создаёт только новые точки отказа. Не использовать
несвязанные S3 buckets/кластеры как взаимозаменяемые endpoints.

**Предупреждение:** VRRP сам по себе не исключает конфликт VIP при
сетевом разделении. 0.51.4 отдельно вводит проверенное partition fencing;
текущий выпуск не заявляет split-brain-free в произвольной сети.

## Сетевой/эксплуатационный контракт

1. Два независимых Linux HAProxy/Keepalived host; совместимый HAProxy 2.8+,
   Keepalived, `iproute2` и systemd. Отдельные API/worker hosts из 0.51.2.
   Два VIP в **одной L2 подсети** с адресами обоих LB. Настроить firewall:
   VRRP unicast между LB, клиентский 443 на public VIP, API/worker трафик
   к PostgreSQL 5432, Redis TLS 6380 и S3 HTTPS 443 на dependency VIP.
   Только LB доступны Patroni REST health port (обычно 8008);
   его не публиковать в интернет. Ограничить и аутентифицировать
   административный SSH. Не соединять независимые VLAN только через VRRP.
2. DNS имена `launcher.example`, `postgres-ha.internal`,
   `redis-ha.internal`, `s3-ha.internal` указывают на нужные VIP. Сертификат
   **каждого** upstream Redis/S3/HTTPS ingress обязан содержать его
   стабильное DNS имя. PostgreSQL должен предъявлять сертификат, который
   проверяется libpq по `postgres-ha.internal` при `sslmode=verify-full`.
   Прокси не расшифровывает трафик клиента.
3. На PostgreSQL узлах Patroni `/primary` возвращает HTTP 200 **только**
   на узле с действующим DCS leader lock; REST API защищён отдельной
   управляющей сетью. Синхронное подтверждение WAL и допустимое RPO
   задаются Patroni/PostgreSQL; прокси не может сделать async replication
   без потерь. Потеря quorum должна блокировать опасные записи.
4. Redis TLS и сертификаты на каждом сервере. Dedicated ACL user для
   health checks имеет только разрешение `INFO replication` и не имеет
   доступа к произвольным ключам. Пароль находится в отдельном `0600`
   файле, не в git, не в `.env` и не в отчёте; в сгенерированном HAProxy
   конфиге AUTH команда записана в RESP hex, что **не является шифрованием**:
   конфиг строго `0600`, доступ root/ограниченного администратора.
   ServerBridge/rate limiting должны оставаться fail-closed при недоступном
   primary. Нельзя без дополнительного протокола гарантировать сохранность
   Redis lease через потерю неподтверждённой репликации (0.51.4).
5. S3 endpoint использует path-style requests к одному object namespace.
   S3 health URL (`/minio/health/cluster` для совместимых MinIO gateways)
   должен означать готовность quorum, не просто готовность HTTP listener.
   Выделить отдельные короткоживущие ключи для активной проверки только
   под `launcher-ha-probe-0513/*`: `PutObject`, `GetObject`, `DeleteObject`.
   Каждый `verify` выполняет подпись AWS SigV4, прямое TLS/SNI подключение
   к каждому UP gateway и сравнение **точного тела** между gateway.
   Если данные не совпадают, статус FAIL независимо от HTTP health.
6. Установить актуальные проверенные пакеты из доверенного репозитория ОС,
   не отключать проверку TLS/CA. Мониторить leader count (должен быть 1),
   ingress/gateway count (не меньше 2 в стабильном состоянии), состояние
   VRRP и результаты реальных приложения /ready/growth.

## Установка на ОБОИХ балансировщиках

Пример: public VIP `10.20.0.100`, dependency VIP `10.20.0.101`,
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

Запускать только с реальным TLS/CA и совпадающими S3 bucket, auth,
release keys на всех API/worker. Код 0.51.2 по-прежнему запрещает локальные
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

`verify` запрашивает живую HAProxy UNIX stats socket, **запрещает два
одновременно доступных writer**, требует 2 ingress+2 S3 gateways, реальный
доступ к /ready, строгие SSH host keys и пробы приложения через его уже
существующий `launcher-api diagnose growth`: PostgreSQL fencing, Redis lease
и S3 read/write/delete. Отдельно выполняет AWS SigV4 PUT→GET между
различными прямыми S3 шлюзами, с TLS hostname verification. Отчёт не
содержит DSN/секреты; отсутствие права или сервера — ошибка, не PASS.

## Разрушающие failure drills (ТОЛЬКО разрешённый staging)

Пример: отключение **текущего** PG writer `pg-a`, если HAProxy stats до
испытания показывает `pg-a` UP. `--target` — независимо сверенный SSH
хост именно этого сервера. SSH должен разрешать *только* необходимые
`sudo -n systemctl stop/start patroni`, аналогично для `redis-server`
или `minio`. Программа проверяет базовое здоровье, останавливает сервис,
ждёт появления другого primary/gateway, проверяет прямую живую API/worker
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
действительные systemd unit names; для управляемых облачных сервисов
использовать провайдерский fault-injection API и отдельно приложить receipts.
Тест остановки Redis требует наличия Sentinel/quorum и работоспособного
promotion. При непредвиденной ошибке SSH система может быть недоступна
даже после попытки восстановления: необходим out-of-band доступ.

Для активного LB — **отдельный** сценарий, запускать НА РЕЗЕРВНОМ LB.
Проверяется факт, что на исходном remote LB был public VIP, на резервном
его не было. Затем отключается HAProxy на активном, проверяется появление
**обоих VIP** на резервном, доступность публичного HTTPS `/ready`,
маршрутов dependencies и опциональные growth проверки API/worker.

```bash
sudo python3 /opt/launcher/scripts/operations/dependency_ha_0513.py edge-drill \
  --env-file /etc/launcher/ha-0513.env --edge-url https://launcher.example \
  --node a=operator@api-a.internal --node b=operator@api-b.internal \
  --target operator@lb-active.internal --allow-disruption \
  --output /var/lib/launcher/ha-0513-lb.json
```

**Фактические результаты**: измерить RTO/RPO для PostgreSQL, Redis,
S3 и ingress отдельно; подтвердить состояние миров, UUID, identities,
реплик и durable jobs; сверить количество подтверждённых writes до/после.
Механизм outage probe не утверждает сохранность всех данных по одному canary,
и не заменяет проверку power-off, разделения сети, Redis lease-split или
выполнения JVM/gameplay. Split-brain и fencing относятся к 0.51.4,
N/N−1 rolling updates — к 0.51.6/0.51.7, restore — к 0.51.8/0.51.9.

## Правила релиза

- **Никогда не объявлять GA PASS по локальным unit tests или `haproxy -c`.**
  Рабочие скрипты и безопасная конфигурация поставляются как код;
  реальное переключение проверяется только на независимых hosts и signed
  receipts точных конечных файлов.
- Два одновременно UP PostgreSQL или Redis writer — FAIL (потенциальный
  split-brain); один доступный gateway S3 позволяет продолжать безопасные
  операции после отказа, но не проходит требование базовой избыточности.
- Два active S3 gateways без общей реплицируемой базы не считаются HA.
- Ошибки сертификатов, ACL, API readiness или неверное содержимое объекта
  блокируют выпуск; TLS verification нельзя отключать ради PASS.
