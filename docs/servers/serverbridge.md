# ServerBridge

ServerBridge связывает Backend Launcher с Minecraft-серверами и прокси. Репозиторий содержит Java-мосты в `plugins/` (в том числе семейства Bukkit/Paper/Purpur/Spigot/Folia, Bungee/Waterfall/Velocity, Fabric/Quilt/Forge/NeoForge и другие предусмотренные модули) и средства регистрации, контроля и хостинга в CLI/backend.

## Логическая последовательность

1. Администратор регистрирует server identity и разрешённый тип моста.
2. На стороне Minecraft-сервера устанавливается релевантный plugin/bridge; он должен соответствовать версии/подписи политики backend.
3. Выполняется enrollment с proof-of-possession и одноразовыми билетами там, где сценарий их требует.
4. Сервер передаёт heartbeat/telemetry, принимает только авторизованные команды и подтверждает события.
5. При отзыве устройства или ключа узел должен перестать выполнять защищённые операции.

Точный состав команд `nl server-bridge detect|install|enroll|status|upgrade|migrate-v3|rollback|host` приведён в `cli/cmd/launcher/main.go`. Методы Backend — в `schemas/openapi.yaml`.

## Защита

Разделяйте ключи узлов, политики выпуска plugin JAR, права операторов и доступ к Backend API. Протокол должен отклонять replay, просроченный challenge, повторную регистрацию существующей identity и несовместимые сообщения. Не отключайте защитные проверки ради удобства установки.

## Проверка

Доступны `scripts/serverbridge/matrix.py`, `scripts/serverbridge/test_matrix.py`, smoke-файлы ServerBridge и Java-модули Gradle. Для production проверяйте серверный JAR/подпись и реальный цикл подключения к серверу — простой unit test не заменяет e2e.
