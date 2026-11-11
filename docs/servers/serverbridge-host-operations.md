# 0.41.3 — серверная часть → удалённое управление → супервизор узла

Это **действующий** путь управления жизненным циклом хоста. Игровые Java-команды ServerBridge и команды процессов хоста намеренно используют разные домены авторизации. Backend не содержит встроенного SSH и не выполняет произвольные удалённые оболочки.

## Подготовьте настоящий узел

1. Настройте установленный игровой сервер командой `nl server-bridge host configure ...`. Команда `nl server-bridge host status --server-root /srv/minecraft/survival` должна сообщать о настроенном процессе Java. Убедитесь, что игровой адаптер зарегистрирован в Backend как узел ServerBridge `survival` с тем же корнем сервера.
2. На хосте инициализируйте идентичность RemoteControl: `nl server-bridge host remote init --server-root /srv/minecraft/survival`.
3. Выдайте **краткоживущий** сервисный токен для исходного адреса Backend: `nl server-bridge host remote issue --server-root /srv/minecraft/survival --subject backend-control --scope host.status --scope host.start --scope host.stop --scope host.restart --source 10.10.0.5/32 --ttl-seconds 900 --token-file /etc/launcher/host-survival.token`. Перевыпускайте токены по мере истечения срока и атомарно обновляйте приватный файл токена. Никогда не сохраняйте токен или закрытые ключи TLS в репозитории.
4. Запустите агент с доверенным сертификатом TLS: `nl server-bridge host remote serve --server-root /srv/minecraft/survival --listen 10.10.0.21:9443 --tls-cert /etc/launcher/host.crt --tls-key /etc/launcher/host.key --allow-source 10.10.0.5/32`. Для обязательного взаимного TLS в промышленной среде используйте `--client-ca` и выдайте соответствующий клиентский сертификат Backend. Ключ RemoteControl и журнал хоста должны оставаться закрытыми внутри этого корня сервера.
5. На Backend создайте доступный владельцу для чтения JSON-файл с правами **0600** по абсолютному пути:

```json
{
  "survival": {
    "url": "https://10.10.0.21:9443",
    "nodeId": "<nodeId RemoteControl, полученный при удалённой инициализации>",
    "caFile": "/etc/launcher/remote-ca.pem",
    "tokenFile": "/etc/launcher/host-survival.token",
    "clientCert": "/etc/launcher/backend.crt",
    "clientKey": "/etc/launcher/backend.key"
  }
}
```

Каждый указанный файл должен иметь абсолютный путь, быть обычным файлом, не символической ссылкой, и быть закрытым для других пользователей (0600). Переменная `LAUNCHER_SERVER_BRIDGE_HOST_TARGETS_FILE` должна указывать на этот реестр. Backend требует TLS 1.3 и проверяет CA, имя/адрес хоста и идентичность узла RemoteControl. Исходящие прокси и перенаправления отключены.

Примените миграцию `0111_server_bridge_host_operations_0413.sql` обычным механизмом Backend/CLI. Команды процессов хоста отключены вне режима развёртывания PostgreSQL. Для учётной записи необходимы ГЛОБАЛЬНОЕ разрешение `host:process`, видимость проекта и свежее подтверждение MFA. Владелец проекта с одними лишь средствами управления игровым сервером **не может** запускать и останавливать физический хост.

## Настоящий вызов API

```sh
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer <authenticated-admin-access-token>' \
  -H 'Idempotency-Key: host-survival-start-20261030' \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}' \
  'https://backend.example/api/v1/server-bridge/servers/survival/host/operations'
```

Сохраните `data.operation.id` из ответа. Для повторов **того же** пользовательского намерения используйте тот же ключ; не создавайте новый, чтобы обойти `indeterminate`. Проверяйте состояние без повторного выполнения команды:

```
GET /api/v1/server-bridge/servers/survival/host/operations/{operationId}
GET /api/v1/server-bridge/servers/survival/host/operations/{operationId}?refresh=1
```

`refresh=1` повторно читает состояние процесса ОС на хосте и идентичность Runtime ServerBridge, но не отправляет POST в RemoteControl. Состояние `succeeded` требует сохранённую агентом квитанцию `succeeded`, независимое подтверждение соответствующего действующего Supervisor/JVM и (для start/restart) более новый heartbeat ServerBridge от нового Runtime. Пока процесс Java работает, но его адаптер Bridge не зарегистрирован, состояние остаётся `accepted`.

Если Backend или хост завершается аварийно в неопределённый момент, в журнале сохраняется `indeterminate`. Другой ключ для сервера блокируется, пока оператор не проверит устойчивую операцию Backend и журнал RemoteControl командой `nl server-bridge host remote inspect --server-root ... --idempotency-key nl-host-<operationId>`. В этом выпуске запрещены автоматический повтор команды, повторное направление по аренде и заявления о подтверждённом успехе. Восстановление после действительно неизвестного исхода требует отдельно аудируемой ручной процедуры.

## Границы и известные ограничения

- Успешный перезапуск хоста не означает готовности приложения Minecraft; ServerBridge должен сообщить новую идентичность Runtime, отличающуюся от прежней. Серверы Vanilla без зарегистрированного агента ServerBridge нельзя считать проверенными сквозным тестом.
- Срок действия токена RemoteControl — не более 15 минут; обновляйте его заранее через механизм распределения секретов оператора.
- Эти маршруты не предоставляют выполнение shell-команд или произвольных аргументов JVM.
- Доставка HTTP-квитанции, фиксация PostgreSQL, настоящий процесс Java и реальная активация плагина должны пройти собственные E2E-тесты подготовленной среды до объявления конфигурации сертифицированной для промышленной эксплуатации.
