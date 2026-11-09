/** Русские названия полей в таблицах и карточках. Ключи API и данные не изменяются. */
const fieldLabels: Readonly<Record<string, string>> = {
  id: 'ID', name: 'Название', displayName: 'Отображаемое имя', title: 'Заголовок',
  description: 'Описание', email: 'Электронная почта', username: 'Имя пользователя',
  projectId: 'ID проекта', profileId: 'ID профиля', channelId: 'ID канала',
  ownerId: 'ID владельца', userId: 'ID пользователя', roleId: 'ID роли',
  deviceId: 'ID устройства', sessionId: 'ID сессии', serverId: 'ID сервера',
  nodeId: 'ID узла', packageId: 'ID пакета', jobId: 'ID задания',
  operationId: 'ID операции', releaseId: 'ID выпуска', commandId: 'ID команды',
  requestId: 'ID запроса', correlationId: 'ID корреляции',
  targetId: 'ID объекта', extensionId: 'ID расширения', publisherId: 'ID издателя',
  providerId: 'ID провайдера', resourceId: 'ID ресурса',
  owner: 'Владелец', actor: 'Инициатор', target: 'Объект', source: 'Источник',
  nameHash: 'Хеш имени', fingerprint: 'Отпечаток ключа',
  status: 'Состояние', state: 'Состояние', trustState: 'Состояние доверия',
  integrityStatus: 'Проверка целостности', protocolMode: 'Режим протокола',
  telemetryState: 'Состояние телеметрии', riskState: 'Состояние риска',
  riskLevel: 'Уровень риска', health: 'Работоспособность',
  action: 'Действие', commandType: 'Тип команды', kind: 'Тип операции',
  type: 'Тип', scope: 'Область действия', mode: 'Режим',
  reason: 'Причина', reasonCode: 'Код причины', error: 'Ошибка',
  lastError: 'Последняя ошибка', message: 'Сообщение', result: 'Результат',
  warning: 'Предупреждение', code: 'Код',
  createdAt: 'Создано', updatedAt: 'Изменено', publishedAt: 'Опубликовано',
  startedAt: 'Начато', finishedAt: 'Завершено', expiresAt: 'Истекает',
  revokedAt: 'Отозвано', lastSeenAt: 'Последняя активность',
  lastLoginAt: 'Последний вход', checkedAt: 'Проверено',
  enabled: 'Включено', disabled: 'Отключено', isDefault: 'По умолчанию',
  protected: 'Защищено', active: 'Активно', online: 'В сети',
  eligible: 'Допущено', verified: 'Проверено',
  count: 'Количество', total: 'Всего', attemptCount: 'Число попыток',
  maxAttempts: 'Максимум попыток', revision: 'Ревизия',
  version: 'Версия', channel: 'Канал', defaultChannel: 'Канал по умолчанию',
  loader: 'Загрузчик', minecraftVersion: 'Версия Minecraft',
  javaMajor: 'Основная версия Java', preset: 'Набор компонентов',
  environment: 'Окружение', platform: 'Платформа', arch: 'Архитектура',
  host: 'Узел', port: 'Порт', ip: 'IP-адрес', url: 'Адрес',
  backendUrl: 'Адрес сервера API', manifestUrl: 'Адрес манифеста',
  keyBinding: 'Привязка ключа', keyAlgorithm: 'Алгоритм ключа',
  digest: 'Хеш', checksum: 'Контрольная сумма', sha256: 'SHA-256',
  sizeBytes: 'Размер в байтах', durationMs: 'Длительность в мс',
  bytesDownloaded: 'Загружено байт',
  permissions: 'Разрешения', capabilities: 'Возможности', features: 'Функции',
  projects: 'Проекты', profiles: 'Профили', users: 'Пользователи',
  roles: 'Роли', devices: 'Устройства', sessions: 'Сессии',
  packages: 'Пакеты', releases: 'Выпуски', servers: 'Серверы',
  extensions: 'Расширения', jobs: 'Задания', operations: 'Операции',
  channels: 'Каналы', events: 'События',
  config: 'Конфигурация', settings: 'Настройки', metadata: 'Метаданные',
  details: 'Подробности', notes: 'Примечания',
};

/** Неизвестное имя поля остаётся исходным; при наведении оно доступно полностью. */
export function resourceFieldRu(field: string): string {
  return fieldLabels[field] ?? field;
}

/** Локализуется только текстовое представление, логическое значение не меняется. */
export function resourceBooleanRu(value: unknown): string | null {
  return typeof value === 'boolean' ? (value ? 'Да' : 'Нет') : null;
}
