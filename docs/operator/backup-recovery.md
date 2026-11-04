# Backup/Restore: три независимые процедуры

Перед остановкой запишите идентификатор проекта, версию, активные сервисы и момент UTC. Обеспечьте maintenance-window и остановите **все** пишущие процессы, включая посторонние интеграции и Minecraft JVM при создании снимка миров. Резервная копия БД без соответствующих blobs/секретов не образует восстановимую установку. Храните backup вне каталога данных; непроверенный архив нельзя автоматически объявлять годным.

## Minimal SQLite: перенос на другой Linux-хост

Остановите systemd API и всех внешних writers. Ключ шифрования храните по отдельному каналу, не в резервируемом каталоге. Установите зависимости `scripts/install/requirements-portable-0452.txt` из доверенного источника.

```sh
umask 077
openssl rand -base64 48 > /etc/launcher/recovery.key
chmod 0600 /etc/launcher/recovery.key
python3 scripts/install/minimal-install.py backup-portable \
  --root /var/lib/launcher-minimal \
  --output /srv/backups/minimal-04513.nmb \
  --passphrase-file /etc/launcher/recovery.key
python3 scripts/install/minimal-install.py verify-portable \
  --input /srv/backups/minimal-04513.nmb \
  --passphrase-file /etc/launcher/recovery.key
sha256sum /srv/backups/minimal-04513.nmb
```

На **другом** хосте с прежним доверенным API 0.45.14 и отдельной доставкой ключа:

```sh
python3 scripts/install/minimal-install.py restore-portable \
  --input /srv/backups/minimal-04513.nmb \
  --target-root /srv/recovery/launcher-minimal \
  --passphrase-file /etc/launcher/recovery.key
python3 scripts/install/minimal-install.py check \
  --env-file /srv/recovery/launcher-minimal/config/backend.env \
  --binary /opt/launcher/bin/launcher-api
```

Восстановите **отдельно** TLS, systemd unit, reverse proxy и DNS. Затем поднимите API, проверьте вход **старого** владельца, сохранённый проект, доступность реальных файлов, невозможность повторного bootstrap. Не запускайте старый и новый хост одновременно с записью в одну логическую установку. [Точная процедура](../deployment/minimal-recovery.md).

## Standard: холодная PostgreSQL/volumes копия

Внутри резервной копии находятся PostgreSQL dump, локальное хранилище и SQLite coordinator. Вне неё — `.env`, TLS, signing keys, внешний auth-provider и Minecraft-миры. Сохраните внешние секреты в менеджере секретов, отключите других SQL-клиентов и writers в Docker volumes.

```sh
sudo python3 scripts/operations/dr_03512.py backup \
  --project launcher --confirm launcher \
  --env-file deploy/production/.env \
  --snapshot /srv/backups/standard-04513 \
  --production-source --maintenance-approved
sudo python3 scripts/operations/dr_03512.py verify \
  --snapshot /srv/backups/standard-04513
```

На новом хосте: идентичная версия Docker-образов и секретов; пустые Docker volumes и контейнеры; TLS/HTTPS должны указывать на новый хост (не на исходный DNS endpoint). Пример **разрушающей операции только на чистом целевом project**:

```sh
sudo python3 scripts/operations/dr_03512.py restore-fresh \
  --project launcher --confirm launcher \
  --env-file deploy/production/.env \
  --snapshot /srv/backups/standard-04513 \
  --ready-url https://recovery.example.org/ready \
  --production-target --maintenance-approved
```

Проверьте прямую готовность восстановленного контейнера, затем публичный URL, старого владельца и blobs. [Ограничения](../releases/0.45.3-standard-backup-restore.md).

## Network-HA: worlds, PostgreSQL, S3 и fencing

Остановите Minecraft JVM/сохраните миры через [механизм world-backup](../servers/serverbridge-world-backup.md), затем прекратите всех API/workers и внешних writers. Используйте `dr_03512.py backup --network-ha` с действительным S3 bucket и повторяемыми `--world-backup name=/absolute/backup-id`; проверяйте снимок штатной командой `verify`. Для восстановления используйте **новый** S3 bucket, новые пустые volumes и `--world-destination name=/absolute/fresh/server-root` для каждого сохранённого мира. Подробная последовательность и обязательные аргументы даны в [Network-HA Recovery](../releases/0.45.4-network-ha-recovery.md).

**Запрещено** переносить прежний Redis AOF и leases: восстановление запускает чистый Redis и требует PostgreSQL fencing незавершённых команд/активных игровых сессий до запуска API. После этого ServerBridge повторно регистрируется. Старые команды не должны выполняться с восстановленным token. Нет автоматического запуска игрового сервера до явной проверки миров, аккаунтов, инвентарей и состояния узлов.

Независимая проверка восстановления и RPO/RTO: [Disaster Recovery](../releases/0.45.6-chaos-disaster-recovery.md). Обязательны отрицательные тесты повреждённого снимка и неуспешного fencing. Ни `verify`, ни успешный `/ready` не доказывают восстановление игрового мира и сессии Minecraft.
