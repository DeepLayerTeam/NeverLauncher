# ServerBridge Bukkit-family — 0.41.5

## Исполняемые команды и уровень подтверждения

Рабочий обработчик `BukkitFamilyBridgePlugin` установлен в артефактах Spigot, Paper, Purpur и Folia. Он выполняет вызовы платформы через основной Bukkit scheduler или через Folia GlobalRegionScheduler / EntityScheduler (для действий с игроками). Нельзя вызывать Bukkit API непосредственно из потока сетевого poller.

| Команда | Подтверждение | Ограничение |
|---|---|---|
| `server.maintenance`, `server.drain` | `succeeded`, локально проверено состояние режима admission/routing | Подтверждение отражает собственное состояние агента |
| `whitelist.add/remove/enable/disable` | `succeeded` при совпадении фактического Bukkit readback | Вызов диспетчера без эффекта — `indeterminate` |
| `ban.add/remove` | `succeeded` только при соответствии `OfflinePlayer.isBanned()` | При недоступном readback — `indeterminate` |
| `player.kick` | `succeeded` только при наблюдении `PlayerQuitEvent` для UUID игрока | При тайм-ауте или остановке плагина — `indeterminate`; повтор автоматически запрещён журналом |
| `message.broadcast` | `executed` после успешного platform вызова / доставки в entity scheduler | Нельзя подтвердить фактическое прочтение сообщения клиентом; частичная ошибка Folia — `indeterminate` |
| `server.save` | `executed` после принятия `save-all flush` | Нет достоверного подтверждения fsync / целостности мира; это не backup |
| `server.console` | `executed` после успешного allowlisted dispatch | Эффект произвольной команды не верифицируется |
| `server.shutdown` | `accepted` после постановки в планировщик | Реальное завершение JVM подтверждает Host Supervisor, не Bukkit plugin |

Backend сохраняет результат в журнале ServerBridge и независимо проверяет тип доказательства и исходный payload для `player.kick`, ban/whitelist и режимов. ACK подписывает зарегистрированный агент; независимой аттестацией игрового мира со стороны Backend он не является.

## Проверки

```bash
python3 e2e/scripts/test-bukkit-control-0415.py
# На CI с Go 1.27.3 и доступными модулями:
cd services/api && go test ./internal/httpapi -run 'TestBridgeOutcomeClassification0411' -count=1
```

Эмуляция API в offline-тесте не заменяет реальную серверную сертификацию. Перед publication запустите каждый *конкретный* релизный JAR на версии игры, поддерживаемой матрицей: плагин должен загрузиться без IllegalAccess/NoSuchMethod, пройти signed heartbeat/control-lease, затем выполнить и проверить whitelist/ban/kick/console/save/maintenance/drain/broadcast. Проверьте исход при отключении Backend и агента до/после ACK; ни один повторный poll не должен физически повторить команду. Для Folia обязателен тест на соседних регионах, миграцию игрока между регионами и retirement entity task. Зафиксируйте в отчёте версию Minecraft, билд ядра, Java, SHA-256 JAR и статусы операций. Если хотя бы один результат не доказан, он не должен маркироваться `succeeded` или «сертифицирован».
