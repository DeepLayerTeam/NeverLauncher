# NeverLauncher 0.21.9 — ServerBridge Operations

## Развёртывание

1. Примените миграцию `0054_serverbridge_operator_0219.sql` штатным механизмом миграций Backend. Она добавляет существующей роли `operator` право `serverbridge:control`, но **не** `serverbridge:console`; кастомным ролям права выдаются отдельно. Внутри проекта полномочия ограничены реальным `projectRoles` пользователя.
2. Разверните Backend и Admin из одного коммита и перезапустите API. Protocol v3 и сетевые контракты Bridge/ACK не меняются, node plugin заменять не требуется.
3. В Admin выберите проект → **ServerBridge**. Для команд потребуется действующая аутентификация с MFA не старше пяти минут. Раздел «Безопасность сессии и passkeys» позволяет пройти phishing-resistant step-up.
4. Проверьте жизненный цикл на действующем узле: `server.save` → `pending` → `leased` → Bridge ACK `succeeded`/`failed`/`indeterminate`. Не считайте `leased` доставкой или исполнением. Проверяйте actual server state при неопределённом исходе.

## Действующий REST API

- `GET /api/v1/server-bridge/projects/{projectId}/overview` — данные только выбранного проекта; сервер проверяет `project:read`, фильтрует nodes, topology, commands и audit. Глобальный `GET /api/v1/server-bridge/overview` сохранён и по-прежнему требует глобальный `project:read`.
- `POST /api/v1/server-bridge/servers/{serverId}/control` — **существующий** протокол команд с type/payload/idempotencyKey и fresh MFA, `serverbridge:control`. Для console также `serverbridge:console`. Авторизация по проекту сервера и криптографическая runtime identity проверяются Backend.
- `GET /api/v1/server-bridge/servers/{serverId}/control/{commandId}` — подробности команды и терминальный ACK.

## Статусы и достоверность

| Состояние БД v3 | Отображение Admin | Гарантия |
|---|---|---|
| `pending` | queued | Запрос сохранён, доставки нет |
| `leased` | dispatched | Задание арендовано bridge poll, доставки/выполнения ещё нет |
| `succeeded` | executed | Bridge прислал подтверждённый успешный ACK |
| `failed` / `unsupported` | failed | Bridge подтвердил неуспех |
| `indeterminate` / `expired` | indeterminate | Исход не подтверждён; не создавать слепо повтор |

У ServerBridge v3 нет самостоятельного подтверждённого промежуточного состояния `delivered` перед execution ACK. Admin **не фабрикует** такое состояние по `leased`: оно отображается только при явном статусе `delivered`, если когда-либо будет поддержано согласованным контрактом. События delivery и ACK в audit служат диагностикой, но не подменяют статус команды. Протокол v3 не изменён.

Снимок telemetry можно использовать, лишь если heartbeat/снимок свежие (<=120 секунд), snapshot Admin получен недавно, а `runtimeId` и `runtimeEpoch` совпадают. Несовпадение, отсутствие данных или задержка отображаются как unknown/stale, а не `0` игроков / TPS. Число игроков доступно, список никнеймов отсутствует в текущем telemetry v3. Для player.kick/ban имя вводится вручную.

При потере HTTP-ответа браузер хранит исходный payload и idempotency key в `sessionStorage`. Кнопка «Повторить с тем же ключом» использует исходное тело запроса. Создавать **новую** команду после неопределённого исхода следует только после проверки реального состояния сервера. После получения ID команда отслеживается по отдельному endpoint независимо от обновления страницы; последние команды доступны в overview.

## Ограничения проверки

Нужно выполнить production Vite build с официальными типами React, Go integration tests на реальной БД PostgreSQL, подписанные heartbeat/ACK от v3 узла и browser E2E с реальным MFA. Без этих проверок GA эксплуатацию нельзя считать сертифицированной.
