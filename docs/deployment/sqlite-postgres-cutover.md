# Launcher 0.47.5 — автономный SQLite → PostgreSQL: процедуры оператора и безопасность переключения

**Статус: кандидат исходников, промышленное переключение ЗАБЛОКИРОВАНО из-за отсутствия полноты данных источника.** Импортёр SQLite Core 0.47.4 заполняет PostgreSQL SQLRepository, но не переносит отдельный снимок `http.sqlite`, `coordinator.sqlite`, все состояния расширений и внешние хранилища Runtime. CLI намеренно не превращает `readyForBackendCutover=false` в положительную сертификацию. Флага обхода нет. Запускать промышленный Backend PostgreSQL только по этим квитанциям запрещено.

## Что действительно делает оператор

`python3 scripts/operations/sqlite_pg_cutover_0475.py` обеспечивает долговременный локальный сценарий оператора с приватными журналами, `flock` единственного владельца, проверкой источника, независимой резервной копией Core с доказательством восстановления, остановкой и проверкой неактивности служб-писателей, замороженной копией Core/HTTP/Coordinator, неизменяемым импортом SQLite Core в промежуточном окружении и действующей среде, проверенным переносом файлов и чтением PostgreSQL без записи. Backend также отклоняет запуск на PostgreSQL, где есть live/staging импорт SQLite без полного допуска к переключению. Проверка выполняется **до** инициализации приложения, расширений, рабочих процессов и HTTP listeners. Посторонние PostgreSQL-установки без импорта не затрагиваются.

Средство проверки сверяет SHA-256 квитанции, количество строк каждой отображённой таблицы (включая специальные преобразования), дайджест каталога и данные пользователей/проектов из действительной реализации SQLRepository. Старые квитанции копирования, содержащие только количества, должны быть пересозданы копировщиком 0.47.5. Несопоставленное исходное состояние **не удаляется**.

Для настоящего запуска под systemd на изолированном тестовом стенде:

```bash
# До выполнения разверните launcher-sqlite с изменениями 0.47.5 на Go 1.27.3,
# примените все миграции PostgreSQL к пустому назначению и
# безопасно задайте LAUNCHER_POSTGRES_DSN и секреты MFA.
python3 scripts/operations/sqlite_pg_cutover_0475.py run \
  --work-dir /private/launcher-cutover-0475 \
  --launcher-sqlite /usr/local/bin/launcher-sqlite \
  --source-env /etc/launcher/backend.env \
  --core-db /var/lib/launcher/core.sqlite \
  --http-db /var/lib/launcher/http.sqlite \
  --coordinator-db /var/lib/launcher/coordinator.sqlite \
  --storage-source /var/lib/launcher/objects \
  --storage-target /var/lib/launcher/pg-objects \
  --writer-unit launcher-api.service \
  --writer-unit launcher-worker.service \
  --project existing-project-id \
  --owner-email original-owner@example.invalid

# Проверьте состояние. Учётные данные и DSN в этом журнале не сохраняются.
python3 scripts/operations/sqlite_pg_cutover_0475.py status \
  --work-dir /private/launcher-cutover-0475

# До запуска любых процессов записи PostgreSQL восстановите прежнее окружение/службу SQLite.
python3 scripts/operations/sqlite_pg_cutover_0475.py rollback \
  --work-dir /private/launcher-cutover-0475 \
  --source-env /etc/launcher/backend.env \
  --core-db /var/lib/launcher/core.sqlite \
  --http-db /var/lib/launcher/http.sqlite \
  --storage-source /var/lib/launcher/objects \
  --storage-target /var/lib/launcher/pg-objects \
  --writer-unit launcher-api.service \
  --project existing-project-id \
  --owner-email original-owner@example.invalid
```

`LAUNCHER_POSTGRES_DSN` обязателен в окружении процесса оператора. Для TOTP добавьте `--mfa-key-file <0600 file>` и `--pg-secret-env <variable-name>` к `run`; секретные значения не передавайте флагами. `--writer-unit` должен перечислять **все службы с правом записи**, включая планировщики и супервизоры расширений/Bridge; всё вне systemd нужно независимо заблокировать. Оператор не может доказать остановку неизвестного неуправляемого процесса. Замороженный снимок создаётся только после проверки остановки всех перечисленных служб.

## Семантика сбоев

- Рабочий каталог с правами `0700` содержит `state.json` и fsync-обеспеченный журнал `stages.jsonl` только на добавление. После возобновления завершённый этап пропускается. Неоднозначный коммит PostgreSQL после аварии **не** повторяется автоматически: перед новой работой вручную изучите `sqlite_live_receipts_0473` и согласуйте состояние.
- Исходные файлы Core/HTTP/Coordinator SQLite при импорте не меняются. `rollback` восстанавливает конфигурацию источника и перезапускает systemd-службу только **до** перехода границы новых записей. При сбое сценарий пытается безопасно откатиться после появления проверенной резервной копии; неопределённый результат записывается как ошибка. Замороженные копии тоже должны пройти проверку целостности.
- Неуспешный импорт оставляет PostgreSQL изолированным. Конфликт копирования или неверный SHA-256 блокирует следующие этапы; успех по одному количеству файлов запрещён.
- Backend остаётся заблокированным до будущего переноса и проверки HTTP Repository, Coordinator, расширений, долговременного состояния защиты и остальных активных данных, независимого подтверждения авторизации пользователей, публикации и запуска Minecraft. Чтение owner/project **не доказывает** работу пароля, ServerBridge и полноценный запуск игры.

## Приёмка ещё не завершена

Полные тесты Go 1.27.3, интеграция PostgreSQL, реальная остановка/перезапуск systemd, независимое восстановление/HA fencing, вход владельца, публикация API, ServerBridge и настоящий Minecraft E2E не запускались в контейнере разработки. Версия 0.47.5 не сертифицирована как промышленное GA-переключение.
