export type LocalLaunchSettings = {
  memoryMb: number;
  screenWidth: number;
  screenHeight: number;
  fullscreen: boolean;
  autoEnter: boolean;
  serverHost: string;
  serverPort: number;
  serverId?: string;
  offlineEnabled: boolean;
};

export type ScopedServer = {
  id: string;
  name: string;
  kind: string;
  status: string;
  health: string;
  minecraftVersion?: string;
};

export function scopedServers(payload: unknown): ScopedServer[] {
  const rows = (payload as { items?: unknown })?.items;
  if (!Array.isArray(rows)) throw new Error('Backend returned an invalid server catalog');
  const seen = new Set<string>();
  return rows.filter((row): row is ScopedServer => {
    if (!row || typeof row !== 'object') return false;
    const item = row as ScopedServer;
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(item.id ?? '') || item.status !== 'active' || seen.has(item.id)) return false;
    seen.add(item.id);
    return typeof item.name === 'string' && typeof item.kind === 'string';
  });
}

export function validMinecraftHost(host: string): boolean {
  if (!host || host.length > 253 || !/^[A-Za-z0-9.-]+$/.test(host)) return false;
  return host.split('.').every((part) => part.length > 0 && part.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(part));
}

export function launchPreferences(settings: LocalLaunchSettings, memory: { minimumMb?: number; maximumMb?: number } | undefined, offlineAllowed: boolean, servers: ScopedServer[], requireServer = false, allowDirectServer = false) {
  const min = Math.max(512, memory?.minimumMb || 512);
  const max = Math.min(32768, memory?.maximumMb || 32768);
  if (!Number.isInteger(settings.memoryMb) || settings.memoryMb < min || settings.memoryMb > max || max < min)
    throw new Error(`RAM must be between ${min} and ${max} MB`);
  if (!Number.isInteger(settings.screenWidth) || settings.screenWidth < 640 || settings.screenWidth > 7680 ||
      !Number.isInteger(settings.screenHeight) || settings.screenHeight < 480 || settings.screenHeight > 4320)
    throw new Error('Screen resolution is outside supported bounds');
  if (settings.offlineEnabled && !offlineAllowed) throw new Error('Offline mode is not allowed by the signed Manifest');
  if (settings.offlineEnabled && settings.autoEnter) throw new Error('Offline and server auto-enter are mutually exclusive');
  if (((settings.autoEnter && !allowDirectServer) || requireServer) && (!settings.serverId || !servers.some((server) => server.id === settings.serverId)))
    throw new Error('Select an available server from the profile browser');
  if (settings.autoEnter && (!validMinecraftHost(settings.serverHost) ||
      !Number.isInteger(settings.serverPort) || settings.serverPort < 1 || settings.serverPort > 65535))
    throw new Error('Provide a valid public Minecraft server address and port');
  return {
    memoryMb: settings.memoryMb, width: settings.screenWidth, height: settings.screenHeight,
    fullscreen: settings.fullscreen, autoEnter: settings.autoEnter,
    serverHost: settings.autoEnter ? settings.serverHost : undefined,
    serverPort: settings.autoEnter ? settings.serverPort : undefined,
    offline: settings.offlineEnabled,
  };
}
