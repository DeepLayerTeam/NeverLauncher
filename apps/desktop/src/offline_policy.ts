import type { LocalLaunchSettings } from './desktop_experience';

/** Офлайн-режим — отдельный локальный запуск, а не резервный провайдер аутентификации. */
export function offlineLaunchSettings0358<T extends LocalLaunchSettings>(settings: T, offline: boolean): T {
  if (!offline) return settings;
  // Подписанный набор владельца может автоматически входить на защищённый сервер в
  // режиме ONLINE. Эта настройка не должна применяться к локальной офлайн-игре,
  // даже если владелец заблокировал её изменение на экране настроек.
  return { ...settings, offlineEnabled: true, autoEnter: false, serverId: '', serverHost: '', serverPort: 25565 };
}

export function offlineSelection0358(identity: string, settings: LocalLaunchSettings): {offline: boolean; serverId: string; autoEnter: boolean} {
  const scoped = offlineLaunchSettings0358(settings, identity === 'offline');
  return {offline: identity === 'offline', serverId: scoped.serverId || '', autoEnter: scoped.autoEnter};
}

export function offlineRecovery0358(error: unknown): string {
  const message = String(error);
  if (/bootstrap|first.run|owner.bundle|owner-signed|подписанн.*bundle/i.test(message))
    return 'Установите выданный владельцем подписанный пакет и завершите первый запуск онлайн.';
  if (/signature|ed25519|trust.policy|invalid.signer|подпись|ключ.*подписи/i.test(message))
    return 'Получите у владельца актуальный подписанный пакет; не отключайте проверку подписи.';
  if (/offline.*(disabled|not.allow|denied.*policy)|offline.cache.disabled/i.test(message))
    return 'Этот профиль запрещает автономный режим. Выберите разрешённый профиль или играйте онлайн.';
  if (/profile|channel|pinned.key|scope|release.differs|preset|подписанн.*профил/i.test(message))
    return 'Вернитесь к установленному профилю и каналу или обновите сборку онлайн.';
  if (/cache|cached.manifest|no.cached.manifest/i.test(message))
    return 'Подключитесь к сети, получите подписанный манифест и сохраните кеш автономного режима.';
  if (/not.verified|integrity|missing|invalid|client.files|file.*corrupt|установк/i.test(message))
    return 'Подключитесь к сети и выполните «Восстановить файлы» в разделе загрузок.';
  return 'Повторите проверку кеша автономного режима; при повторении ошибки откройте диагностику.';
}
