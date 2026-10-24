/** 0.26.9: Resolve one and only one game-authentication realm at launch time. */
export type GameLaunchMode0269 = 'official' | 'local' | 'offline';
export type LaunchIntent0269 = {
  identity: GameLaunchMode0269;
  offlineAllowed: boolean;
  autoEnter: boolean;
  serverId?: string;
  hasOfficialProfile: boolean;
};
export function resolveLaunchMode0269(intent: LaunchIntent0269): GameLaunchMode0269 {
  switch (intent.identity) {
    case 'official':
      if (!intent.hasOfficialProfile) throw new Error('Выберите подтверждённый официальный Minecraft-профиль.');
      if (intent.serverId) throw new Error('Official не использует Never ServerBridge ID. Очистите ID сервера и укажите прямой игровой адрес.');
      return 'official';
    case 'offline':
      if (!intent.offlineAllowed) throw new Error('Offline запрещён подписанным игровым профилем.');
      if (intent.autoEnter || intent.serverId) throw new Error('Offline не подключается к ServerBridge или online-mode серверам.');
      return 'offline';
    case 'local':
      return 'local';
    default:
      throw new Error('Неизвестный режим авторизации Minecraft.');
  }
}
