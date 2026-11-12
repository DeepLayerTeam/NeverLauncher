import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusRu } from '../src/admin/status-ru.ts';

test('Коды основных событий аудита отображаются по-русски', () => {
  const samples = {
    'auth:login': 'Вход в учётную запись',
    'auth:refresh:reuse-detected': 'Обнаружено повторное использование токена',
    'release:publish': 'Публикация выпуска',
    'serverbridge:handoff:denied': 'Передача игрока между серверами отклонена',
    'serverbridge:validate-join:allowed': 'Подключение игрока разрешено',
    'guard:attestation:verified': 'Аттестация защиты подтверждена',
    'validation-attestation:key-revoked': 'Ключ подтверждения проверки отозван',
    'installed-and-verified': 'Установлено и проверено',
  };
  for (const [code, expected] of Object.entries(samples)) {
    assert.equal(statusRu(code), expected, code);
  }
});

test('Отображение кода не меняет идентификаторы событий и неизвестные значения', () => {
  const originalCode = 'auth:device:revoke';
  assert.equal(statusRu(originalCode), 'Отзыв доверия к устройству');
  assert.equal(originalCode, 'auth:device:revoke');
  assert.equal(statusRu('external:custom:event'), 'external:custom:event');
  assert.equal(statusRu(undefined), 'Неизвестно');
});

test('Состояния сборки, безопасности и ServerBridge отображаются по-русски', () => {
  const samples = {
    'integrity-check-failed': 'Проверка целостности не пройдена',
    'not-certified': 'Не сертифицировано',
    'repaired-and-verified': 'Восстановлено и проверено',
    'handoff-denied': 'Передача подключения отклонена',
    'manual-intervention-required': 'Требуется вмешательство оператора',
    'events-acknowledged': 'Получение событий подтверждено',
  };
  for (const [value, expected] of Object.entries(samples)) {
    assert.equal(statusRu(value), expected, value);
  }
});

test('Дополнительные коды разных модулей локализованы без изменения самих данных', () => {
  assert.equal(statusRu('observed-not-independently-certified'), 'Наблюдалось без независимой сертификации');
  assert.equal(statusRu('source_tree_unavailable'), 'Дерево исходников недоступно');
  assert.equal(statusRu('registered-new-trust'), 'Зарегистрирована новая политика доверия');
  assert.equal(statusRu('recovery-ready'), 'Готово к восстановлению');
  assert.equal(statusRu('installation-completed-draft-created'), 'Установка завершена, черновик создан');
  assert.equal(statusRu('provider-credential-deleted'), 'Учётные данные провайдера удалены');
  assert.equal(statusRu('ci_observed_review_required'), 'Наблюдалось в CI, требуется проверка');
  assert.equal(statusRu('sandbox-not-prepared'), 'Изоляция не подготовлена');
  assert.equal(statusRu('sandbox-pid-namespace-not-enforced'), 'Изоляция пространства имён процессов не обеспечена');
  assert.equal(statusRu('macos-sandbox-invalid-network-grant'), 'Недопустимый доступ к сети в macOS');
  assert.equal(statusRu('serverbridge-nonexistent'), 'serverbridge-nonexistent');
});

// Проверяем локализацию дополнительных кодов, поступающих из Backend и нативных подсистем.
test('Ошибки ServerBridge, Guard, хоста и изоляции представлены на русском', () => {
  const examples = {
    'serverbridge_event_signature_invalid': 'Недействительная подпись события ServerBridge',
    'serverbridge_control_idempotency_key_required': 'Необходим ключ идемпотентности команды ServerBridge',
    'guard_release_revoked': 'Релиз Guard отозван',
    'host_operation_preflight_failed': 'Предварительная проверка операции хоста не пройдена',
    'sandbox-macos-helper-ready-timeout': 'Превышено время ожидания готовности помощника macOS',
    'network_capacity_revision_conflict': 'Конфликт ревизии лимита подключений',
  };
  for (const [code, expected] of Object.entries(examples)) {
    assert.equal(statusRu(code), expected, code);
  }
  assert.equal(statusRu('unknown_future_status'), 'unknown_future_status');
});


test('События аудита из серверных обработчиков имеют русские подписи', () => {
  const samples = {
      "admin:login": "Вход администратора",
      "admin:login:failed": "Неудачный вход администратора",
      "admin:login:mfa-failed": "Проверка второго фактора администратора не пройдена",
      "admin:login:passkey-required": "Для входа администратора требуется ключ доступа",
      "admin:login:rate-limited": "Ограничена частота попыток входа администратора",
      "admin:logout": "Выход администратора",
      "auth:mfa-disabled": "Двухфакторная аутентификация отключена",
      "auth:mfa-enabled": "Двухфакторная аутентификация включена",
      "auth:mfa-start": "Начата настройка двухфакторной аутентификации",
      "auth:mfa:policy": "Изменена политика многофакторной аутентификации",
      "auth:passkey:login": "Вход с ключом доступа",
      "auth:passkey:registered": "Ключ доступа зарегистрирован",
      "auth:passkey:registration-failed": "Не удалось зарегистрировать ключ доступа",
      "auth:passkey:revoked": "Ключ доступа отозван",
      "auth:refresh-reuse": "Повторное использование токена обновления",
      "auth:refresh-rotate": "Замена токена обновления",
      "auth:session-revoke": "Сеанс отозван",
      "auth:step-up:passkey": "Дополнительная проверка с ключом доступа",
      "auth:user-revoke": "Отзыв сеансов пользователя",
      "backend:config:reload": "Перезагрузка конфигурации сервера",
      "backend:notice:queued": "Уведомление сервера поставлено в очередь",
      "backend:restart:accepted": "Запрос перезапуска сервера принят",
      "backup:create": "Создание резервной копии",
      "backup:restore": "Восстановление из резервной копии",
      "backup:restore-dry-run": "Пробное восстановление резервной копии",
      "bridge:command-complete": "Команда моста завершена",
      "bridge:command-delivered": "Команда моста доставлена",
      "bridge:command-queue": "Команда моста поставлена в очередь",
      "bridge:join-consume": "Билет подключения использован",
      "bridge:join-issue": "Выдан билет подключения",
      "bridge:node-disable": "Узел моста отключён",
      "bridge:node-enroll": "Узел моста зарегистрирован",
      "build-workspace:build": "Сборка рабочей области",
      "build-workspace:create": "Создание рабочей области сборки",
      "build-workspace:import": "Импорт в рабочую область сборки",
      "build-workspace:remove": "Удаление из рабочей области сборки",
      "build-workspace:stage": "Подготовка рабочей области сборки",
      "channel:create": "Создание канала выпусков",
      "channel:update": "Обновление канала выпусков",
      "client-factory:build": "Сборка клиента",
      "client-factory:delete": "Удаление сборки клиента",
      "client-factory:deliver": "Доставка сборки клиента",
      "client-factory:export": "Экспорт сборки клиента",
      "client-factory:modpack-import": "Импорт сборки модов",
      "component-catalog:update": "Обновление каталога компонентов",
      "extension:cli:invoke": "Вызов команды расширения",
      "extension:emergency:clear": "Снятие аварийной блокировки расширения",
      "extension:emergency:disable": "Аварийное отключение расширения",
      "extension:ga:reconcile": "Согласование состояния расширений",
      "extension:host:restart": "Перезапуск хоста расширения",
      "extension:host:start": "Запуск хоста расширения",
      "extension:host:stop": "Остановка хоста расширения",
      "extension:lifecycle:disable": "Отключение расширения",
      "extension:lifecycle:enable": "Включение расширения",
      "extension:lifecycle:install": "Установка расширения",
      "extension:lifecycle:rollback": "Откат расширения",
      "extension:lifecycle:uninstall": "Удаление расширения",
      "extension:lifecycle:update": "Обновление расширения",
      "extension:lifecycle:update-failed": "Не удалось обновить расширение",
      "extension:package-publish": "Публикация пакета расширения",
      "extension:permission:grant": "Выдача разрешения расширению",
      "extension:permission:revoke": "Отзыв разрешения расширения",
      "extension:publisher-status": "Изменение состояния издателя расширений",
      "extension:publisher-trust": "Изменение доверия к издателю расширений",
      "extension:quarantine:release": "Снятие карантина расширения",
      "extension:recovery:backup": "Создание резервной копии расширения",
      "extension:recovery:import": "Импорт данных восстановления расширения",
      "extension:recovery:restore": "Восстановление расширения",
      "extension:registry:channel:set": "Настройка канала реестра расширений",
      "extension:registry:key:add": "Добавление ключа реестра расширений",
      "extension:registry:publish": "Публикация в реестре расширений",
      "extension:registry:publisher:save": "Сохранение издателя в реестре расширений",
      "extension:registry:reject-contract": "Отклонение несовместимого контракта расширения",
      "extension:registry:yank": "Снятие версии расширения с публикации",
      "extension:secret:delete": "Удаление секрета расширения",
      "extension:secret:set": "Сохранение секрета расширения",
      "extension:state-write": "Запись состояния расширения",
      "extension:trust:key:revoke": "Отзыв доверенного ключа расширения",
      "extension:trust:policy": "Изменение политики доверия расширений",
      "extension:update-pin:delete": "Снятие закрепления версии расширения",
      "extension:update-pin:set": "Закрепление версии расширения",
      "extension:update-transaction:failed": "Транзакция обновления расширения завершилась ошибкой",
      "extension:update-transaction:succeeded": "Транзакция обновления расширения завершена",
      "extension:version:register": "Регистрация версии расширения",
      "file:upload": "Загрузка файла",
      "manifest:update": "Обновление манифеста",
      "migration:baseline": "Фиксация исходного состояния миграции",
      "migration:created": "Создание миграции",
      "migration:cutover-activated": "Переключение миграции выполнено",
      "migration:cutover-cancelled": "Переключение миграции отменено",
      "migration:cutover-staged": "Подготовка переключения миграции",
      "migration:dry-run": "Пробный запуск миграции",
      "migration:dry-run-all": "Пробный запуск всех этапов миграции",
      "migration:gravit-compatibility": "Проверка совместимости Gravit",
      "migration:gravit-content-stage": "Подготовка содержимого Gravit",
      "migration:gravit-credentials-import": "Импорт учётных данных Gravit",
      "migration:gravit-identities-mapped": "Сопоставление учётных записей Gravit",
      "migration:gravit-identities-verified": "Проверка учётных записей Gravit",
      "migration:gravit-modules-reviewed": "Проверка модулей Gravit",
      "migration:gravit-optionals": "Обработка необязательных компонентов Gravit",
      "migration:gravit-rehearsal-checked": "Проверка пробного переноса Gravit",
      "migration:gravit-security-reset": "Сброс настроек безопасности Gravit",
      "migration:gravit-source-export": "Экспорт исходных данных Gravit",
      "migration:gravit-source-inventory": "Инвентаризация исходных данных Gravit",
      "migration:paused": "Миграция приостановлена",
      "migration:rc-reviewed": "Проверка кандидата в выпуск миграции",
      "migration:resumed": "Миграция возобновлена",
      "migration:rollback-committed": "Откат миграции выполнен",
      "migration:rollback-planned": "Откат миграции запланирован",
      "migration:serverbridge-new-identity": "Создание новой идентификации ServerBridge при миграции",
      "migrations:apply": "Применение миграций",
      "minecraft:identity-save": "Сохранение учётной записи Minecraft",
      "minecraft:session-created": "Создание сеанса Minecraft",
      "minecraft:session-revoked": "Отзыв сеанса Minecraft",
      "missing:gameserver:traffic": "Отсутствует трафик игрового сервера",
      "operation:cancel": "Отмена операции",
      "operation:enqueue": "Постановка операции в очередь",
      "operation:retry": "Повтор операции",
      "package:create": "Создание пакета",
      "package:file:java-content-transform": "Преобразование содержимого Java-файла пакета",
      "package:file:upload": "Загрузка файла пакета",
      "package:integrity-check": "Проверка целостности пакета",
      "package:runtime-validation": "Проверка пакета в среде выполнения",
      "package:sign": "Подписание пакета",
      "package:stage": "Подготовка пакета",
      "package:store": "Сохранение пакета",
      "package:validate": "Проверка пакета",
      "profile:create": "Создание профиля",
      "profile:import-gravit": "Импорт профиля Gravit",
      "profile:update": "Обновление профиля",
      "project:create": "Создание проекта",
      "project:export": "Экспорт проекта",
      "project:import": "Импорт проекта",
      "project:update": "Обновление проекта",
      "project:validation-policy": "Изменение политики проверки проекта",
      "release-draft:create": "Создание черновика выпуска",
      "release-draft:delete": "Удаление черновика выпуска",
      "release-draft:update": "Обновление черновика выпуска",
      "release:create": "Создание выпуска",
      "system:extensions-ga": "Системная проверка готовности расширений",
      "texture:exception:update": "Изменение исключения политики текстур",
      "texture:policy:update": "Изменение политики текстур",
      "user:create": "Создание пользователя",
      "user:disable": "Отключение пользователя",
      "user:enable": "Включение пользователя",
      "user:password:reset": "Сброс пароля пользователя",
      "user:project-role:granted": "Выдача роли пользователя в проекте",
      "user:update": "Обновление пользователя"
  };
  for (const [code, expected] of Object.entries(samples)) {
    assert.equal(statusRu(code), expected, code);
  }
  assert.equal(statusRu('external:unknown:action'), 'external:unknown:action');
});
