# NeverLauncher 0.48.8 — интеграция Java-приложений с ServerBridge

Java-расширения используют `context.runtime().serverBridge()` для доступа к действующему репозиторию ServerBridge v3 в PostgreSQL через **существующий аутентифицированный брокер Go Extension Host**. Это эксплуатационная интеграция, а не альтернативный сервер ServerBridge, API прямого SQL, точка аутентификации Minecraft или изменение classpath внутри процесса. SDK совместим с Java 17, включая хосты Java 21.

## Действующие данные и разрешения

| Вызов Java SDK | Операция брокера | Необходимые действующие разрешения |
| --- | --- | --- |
| `serverBridge().servers(projectId, offset, limit)` | `bridge.servers` | `serverbridge:read` |
| `serverBridge().server(projectId, serverId)` | `bridge.server` | `serverbridge:read` |
| `serverBridge().pendingJoinTicket(projectId, serverId, username)` | `bridge.access.ticket` | `serverbridge:read`, `project:read` |
| `serverBridge().command(...)` | `bridge.command.create` | `serverbridge:read` и разрешение игрового домена по типу команды |
| `serverBridge().commandStatus(projectId, serverId, id)` | `bridge.command.get` | `serverbridge:read` и разрешение игрового домена по сохранённому типу команды |
| `serverBridge().subscribeEvents(listener)` | Существующая шина EventBus `serverbridge.event.received` | `events:subscribe`, `serverbridge:read` |

Все чтения данных ограничены явно указанным ID проекта и областью действия установки; список содержит не более 50 записей на запрос. Брокер повторно проверяет разрешения после доступа к данным и до возврата ответа. В код Java не передаются сохранённые учётные данные узла, открытые ключи, хеши отпечатков, аргументы команд, сведения об инициаторе, необработанные токены аренды/ACK и хеши запросов.

**Проверка доступа носит только справочный характер.** `pendingJoinTicket()` сообщает, существует ли действующий билет, выданный NeverLauncher для запрошенных сервера и игрока и привязанный к эпохе идентичности узла. Метод НЕ разрешает вход, не выдаёт и не расходует билет и не проверяет идентичность Mojang/Microsoft. Фактический допуск выполняется исключительно через аутентифицированный ServerBridge `hasJoined` с одноразовым погашением билета, непрерывной проверкой доверия и официальной проверкой Minecraft.

## Управление через очередь, без команд ОС

Метод `command()` помещает запись в существующее устойчивое хранилище команд ServerBridge v3. При добавлении возвращаются состояние `pending` и ID команды; это **не** означает, что игровой сервер выполнил её. Для достоверного состояния вызовите `commandStatus()`.

Поддерживаемые команды и разрешения игрового домена:

- `message.broadcast`: `gameserver:broadcast` (требуется `message`)
- `player.kick`, `whitelist.add/remove/enable/disable`, `ban.add/remove`: `gameserver:moderate`
- `server.save`: `gameserver:save`
- `server.maintenance`, `server.drain`: `gameserver:traffic` (требуется `enabled: true|false`)

Брокер Go отклоняет `server.console`, `server.shutdown`, произвольные команды оболочки и команды управления хостом. Он проверяет аргументы, подписанные возможности Runtime, ограничения семейства адаптеров, метку времени последнего наблюдения Runtime, эпоху идентичности и проверенный хеш интеграции. PostgreSQL защищает создание команд от подмены Runtime, сохраняет канонический SHA-256, обеспечивает уникальность пары сервер + инициатор + ключ идемпотентности и ведёт аудит. Ключ идемпотентности обязателен (8–128 символов); срок действия — 10–600 секунд, по умолчанию 120. Только существующий подписанный узел Bridge вправе арендовать и подтверждать команду из очереди. Расширение не может подделать ACK или учётные данные доставки.

## Пример Java

```java
var bridge = context.runtime().serverBridge();
var node = bridge.server("my-project", "my-server");
if (node.runtimeActive()) {
    var receipt = bridge.command(
        "my-project", "my-server", "message.broadcast",
        java.util.Map.of("message", "Техническое обслуживание сервера через 5 минут"),
        "maintenance-notice-20261102", 120);
    var state = bridge.commandStatus(
        "my-project", "my-server", receipt.command().id());
    // state.status() — устойчивое состояние очереди, не результат синхронного выполнения.
}
bridge.subscribeEvents(event -> {
    var payload = event.event();
    // Устойчивая доставка как минимум один раз; исключайте повторные внешние побочные эффекты.
    System.out.println(payload.serverId() + ":" + payload.type());
});
```

## Проверка и оставшиеся условия выпуска

Выполните `sh sdk/java/core/build.sh test`. Новый набор тестов Java использует действительный HTTP-сервер loopback с bearer-аутентификацией и согласованием возможностей, а не имитацию Java `HostSession`. В CI запускайте тесты аутентифицированного HTTP брокера Go, тесты содержимого и fencing и уже существующий интеграционный набор для устойчивых команд PostgreSQL на Go 1.27.3. До приёмки GA необходимо завершить интеграционные проверки полного подписанного пакета, Java 17/21 и реального адаптера Minecraft. Обновление исходников не отменяет блокирующие условия выпуска, действующие с 0.48.0+.
