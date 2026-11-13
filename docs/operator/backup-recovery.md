# Резервное копирование и восстановление: три независимые процедуры

Перед остановкой запишите идентификатор проекта, версию, активные сервисы и момент UTC. Запланируйте окно технического обслуживания и остановите **все** пишущие процессы, включая сторонние интеграции и процесс Minecraft JVM при создании снимка миров. Резервная копия БД без соответствующих файловых объектов и секретов не образует восстановимую установку. Храните резервные копии вне каталога данных; непроверенный архив нельзя автоматически объявлять годным.

## Минимальный режим (Minimal, SQLite): перенос на другой Linux-хост

Остановите systemd API и всех сторонних процессов записи. Ключ шифрования храните по отдельному каналу, не в резервируемом каталоге. Установите зависимости `scripts/install/requirements-portable.txt` из доверенного источника.

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

Восстановите **отдельно** TLS, службу systemd, обратный прокси-сервер и DNS. Затем поднимите API, проверьте вход **старого** владельца, сохранённый проект, доступность реальных файлов, невозможность повторной первоначальной настройки. Не запускайте старый и новый хост одновременно с записью в одну логическую установку. [Точная процедура](../deployment/minimal-recovery.md).

## Стандартный режим (Standard): холодная копия PostgreSQL и томов данных

Внутри резервной копии находятся дамп PostgreSQL, локальное хранилище и координатор SQLite. Вне неё — `.env`, TLS, ключи подписи, внешний провайдер авторизации и Minecraft-миры. Сохраните внешние секреты в менеджере секретов, отключите других SQL-клиентов и процессов, записывающих данные в тома Docker.

```sh
sudo python3 scripts/operations/dr.py backup \
  --project launcher --confirm launcher \
  --env-file deploy/production/.env \
  --snapshot /srv/backups/standard-04513 \
  --production-source --maintenance-approved
sudo python3 scripts/operations/dr.py verify \
  --snapshot /srv/backups/standard-04513
```

На новом хосте: идентичная версия Docker-образов и секретов; пустые тома Docker и контейнеры; TLS/HTTPS должны указывать на новый хост (не на исходный адрес DNS). Пример **разрушающей операции только на чистом целевом проекте**:

```sh
sudo python3 scripts/operations/dr.py restore-fresh \
  --project launcher --confirm launcher \
  --env-file deploy/production/.env \
  --snapshot /srv/backups/standard-04513 \
  --ready-url https://recovery.example.org/ready \
  --production-target --maintenance-approved
```

Проверьте прямую готовность восстановленного контейнера, затем публичный URL, учётную запись прежнего владельца и файловые объекты. [Ограничения](../deployment/consistent-backup-pitr.md).

## Режим высокой доступности (Network-HA): миры, PostgreSQL, S3 и защита от устаревших владельцев

Остановите Minecraft JVM/сохраните миры через [механизм world-backup](../servers/serverbridge-world-backup.md), затем прекратите все процессы API, обработчиков и сторонние процессы записи. Используйте `dr.py backup --network-ha` с действующим бакетом S3 и повторяемыми `--world-backup name=/absolute/backup-id`; проверяйте снимок штатной командой `verify`. Для восстановления используйте **новый** бакет S3, новые пустые тома данных и `--world-destination name=/absolute/fresh/server-root` для каждого сохранённого мира. Подробная последовательность и обязательные аргументы даны в [Network-HA Recovery](../operations/physical-ha-disaster-recovery.md).

**Запрещено** переносить прежний журнал Redis AOF и данные об аренде: восстановление запускает чистый Redis и требует блокировку устаревших владельцев в PostgreSQL для незавершённых команд/активных игровых сессий до запуска API. После этого ServerBridge повторно регистрируется. Старые команды не должны выполняться с восстановленным токеном. Нет автоматического запуска игрового сервера до явной проверки миров, аккаунтов, инвентарей и состояния узлов.

Независимая проверка восстановления и показателей RPO/RTO: [«Аварийное восстановление» (Disaster Recovery)](../deployment/cross-host-disaster-recovery.md). Обязательны отрицательные тесты повреждённого снимка и неуспешной блокировки устаревших владельцев. Ни `verify`, ни успешный `/ready` не доказывают восстановление игрового мира и сессии Minecraft.
