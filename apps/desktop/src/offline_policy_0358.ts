import type { LocalLaunchSettings } from './desktop_experience_0229';

/** Offline is a distinct local-only launch, not a fallback auth provider. */
export function offlineLaunchSettings0358<T extends LocalLaunchSettings>(settings: T, offline: boolean): T {
  if (!offline) return settings;
  // A signed owner bundle may auto-enter a protected server in ONLINE mode.
  // That setting must not be used for local offline play, even if it is locked
  // by the owner and therefore cannot be changed through the Settings screen.
  return { ...settings, offlineEnabled: true, autoEnter: false, serverId: '', serverHost: '', serverPort: 25565 };
}

export function offlineSelection0358(identity: string, settings: LocalLaunchSettings): {offline: boolean; serverId: string; autoEnter: boolean} {
  const scoped = offlineLaunchSettings0358(settings, identity === 'offline');
  return {offline: identity === 'offline', serverId: scoped.serverId || '', autoEnter: scoped.autoEnter};
}

export function offlineRecovery0358(error: unknown): string {
  const message = String(error);
  if (/bootstrap|first.run|owner.bundle|owner-signed|подписанн.*bundle/i.test(message))
    return 'Установите выданный владельцем подписанный bundle и завершите первый запуск онлайн.';
  if (/signature|ed25519|trust.policy|invalid.signer|подпись|ключ.*подписи/i.test(message))
    return 'Получите у владельца актуальный подписанный bundle; не отключайте проверку подписи.';
  if (/offline.*(disabled|not.allow|denied.*policy)|offline.cache.disabled/i.test(message))
    return 'Этот профиль запрещает offline. Выберите разрешённый профиль или играйте онлайн.';
  if (/profile|channel|pinned.key|scope|release.differs|preset|подписанн.*профил/i.test(message))
    return 'Вернитесь к установленному профилю и каналу или обновите сборку онлайн.';
  if (/cache|cached.manifest|no.cached.manifest/i.test(message))
    return 'Подключитесь к сети, получите подписанный манифест и сохраните offline-кеш.';
  if (/not.verified|integrity|missing|invalid|client.files|file.*corrupt|установк/i.test(message))
    return 'Подключитесь к сети и выполните «Восстановить файлы» в разделе загрузок.';
  return 'Повторите проверку offline-кеша; при повторении ошибки откройте диагностику.';
}
