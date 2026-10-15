# Поиск неисправностей

## API не стартует / `/ready` возвращает ошибку

Проверьте DSN PostgreSQL, миграции, учётные данные Redis, права storage, секреты подписи и required release allowlists. Production backend намеренно блокирует небезопасную конфигурацию. Не отключайте проверки готовности вместо устранения первопричины.

## Desktop не запускает Minecraft

Зафиксируйте ОС/архитектуру, Java major version, Minecraft version, загрузчик, выбранный профиль/канал, manifest SHA и обезличенную диагностику. Проверьте доступность upstream и соответствие статусов [матрице](../clients/compatibility.md). Не считайте ряд `required: false` сертифицированным.

## ServerBridge не регистрируется

Проверьте совместимость server/plugin JAR, ключи identity, одноразовый enrollment, статус узла и сетевой доступ. Если отказ связан с повторной регистрацией, проверьте процесс безопасной ротации identity: прямое overwrite уже зарегистрированного ключа недопустимо.

## Расширение не стартует

Проверьте signature/registry, explicit grants, host limits, секреты и audit events. Quarantine/disabled state нельзя игнорировать. См. [NeverExtensions](../extensions/overview.md).

## Диагностика без секретов

Используйте группы `nl diagnostics collect|redact|validate|bundle` и `nl operations diagnostics`. Перед загрузкой логов удалите пароли, access/refresh tokens, приватные ключи, DSN и персональные данные. Общие проблемы с CI: [ci.md](ci.md).
