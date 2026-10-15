# Миграции и обновления

## Перед обновлением

- Установите точную текущую и целевую версии (`VERSION`, package manifests, Git SHA).
- Снимите проверенный backup PostgreSQL и file storage; сохраните служебные секреты **отдельно** от архива приложения.
- Убедитесь в наличии политики подписей/allowlist нового Guard и ServerBridge; проверьте совместимость API и конфигураций расширений.
- Проверьте достаточное место для staging и отката.

## Данные Backend

Миграции находятся в `services/api/internal/repository/postgres/` и связанных модулях. CLI имеет команды `nl db migrations|migration-doctor|migrate|status|validate`. **Не применяйте миграции на production до резервного копирования.** Не изменяйте ранее применённые SQL-файлы: создавайте новую миграцию.

## Desktop/Runtime/Extensions

CLI содержит transactional updater `nl update plan|apply|status|recover` и операции rollback/update для расширений. Сначала проверяйте подписи и все SHA-256, затем осуществляйте замену; при сбое восстанавливайте согласованное состояние. Для дополнительной диагностики используйте `nl diagnostics ...` и `nl release doctor`.

## После обновления

Проверьте `/ready`, работу входа, выдачу профилей/пакетов, загрузку Minecraft, registration/heartbeat ServerBridge и статусы расширений. Сохраняйте логи без персональных данных и токенов.
