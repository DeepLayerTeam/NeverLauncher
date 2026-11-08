# Высокая доступность, мониторинг и разбор инцидента

Операционные проверки выполняются только при разрешённом окне обслуживания; отказ PostgreSQL, Redis или S3 в боевой системе ради проверки запрещён. Сначала включите режим обслуживания, зафиксируйте UTC и отказавшие зависимости, затем собирайте очищенную диагностику и выполняйте восстановление по пошаговому руководству. Не публикуйте логи со значениями токенов, URL с параметрами запроса, частными IP или переменные окружения Docker.

## Наблюдаемость

Существующий [Observability](../releases/0.45.9-observability.md) использует метрики API, JSON request logs, `X-Correlation-ID`, Prometheus, Blackbox Exporter, Alertmanager и сборщик инцидентов. Отключённый receiver/непроверенная доставка уведомления — `NOT RUN`, а не здоровая система.

```sh
python3 scripts/operations/observability_0459.py configure \
  --webhook-url-file /etc/launcher/alert-webhook-url \
  --output /etc/launcher/alertmanager.yml
python3 scripts/operations/observability_0459.py incident \
  --project launcher --version 0.45.14 --since 15m \
  --compose deploy/production/docker-compose.yml \
  --output /var/tmp/launcher-incident.json.zip
```

Для HA добавьте `--overlay deploy/production/docker-compose.network-ha.yml` к сбору инцидента. Созданный архив содержит только разрешённые поля; всё равно проверяйте его перед передачей. Мониторинг должен проверять оба экземпляра API и обработчики задач, не только публичный Nginx.

## Failover в изолированном стенде

1. Сначала прочитать [Multi-node HA](../releases/0.45.5-multi-node-ha.md) и убедиться в существовании **реальной** внешней инфраструктуры PostgreSQL/Redis/S3.
2. Прервать один API, проверить доступ через другой и через Nginx, затем восстановить; повторить в обратную сторону.
3. Выполнить длительную задачу, выключить `worker-a`; после lease expiration `worker-b` должен принять работу без двойного применения изменений. `ready` недостаточен: проверять результат в PostgreSQL и fencing token.
4. В отдельном `nl-dr-*` lab провести [Chaos/Disaster Recovery](../releases/0.45.6-chaos-disaster-recovery.md) с подлинными Docker-остановками PostgreSQL, Redis, S3 и сетевой изоляцией worker.
5. Зафиксировать фактические длительности восстановления и точные отметки последних подтверждённых записей. Возраст снимка — оценка верхней границы возможного RPO, но не доказательство точных потерянных записей.

## Порядок реального disaster restore

Оградите старый cluster от writes/DNS. На свежем хосте восстановите matching-version PostgreSQL, S3 и миры, используйте новую Redis без старых leases. Восстановление блокирует недействующие ServerBridge-сессии, повышает fencing-эпохи и требует повторной регистрации узлов. После успешной независимой проверки — поднимите API/workers и выполните тест Minecraft join. Если restore/проверка fencing не прошли, новый кластер остаётся недоступным.

Команда [restore acceptance](../releases/0.45.6-chaos-disaster-recovery.md) сохраняет отчёт с измеренным RTO и явными ограничениями оценки RPO; не создавайте фиктивные checkpoint и не помечайте отсутствующие доказательства как PASS. При активном инциденте используйте [ведомость](operator-checklist.md).
