import { requestJSON } from './client.ts';

/** Existing ServerBridge v3 REST API. No changes to node protocol, command or ACK envelopes. */
export type ServerBridgeTelemetry = {
  sampledAtUnixMillis?: number; windowMillis?: number; runtimeId?: string; runtimeEpoch?: number;
  playersOnline?: number; playersMax?: number; tps?: number | null; mspt?: number | null;
  tickHealth?: string; heapUsedBytes?: number; heapMaxBytes?: number;
  loadedWorlds?: number; loadedChunks?: number; threadCount?: number; metrics?: string[];
};
export type ServerBridgeNode = {
  id: string; name?: string; projectId: string; profileId?: string; kind?: string;
  status: string; fresh: boolean; lastHeartbeatAt?: string; runtimeId?: string; runtimeEpoch?: number;
  runtimeTransition?: string; hostname?: string; protocolVersion: number; protocolMode?: string;
  protocolMigrationRequired?: boolean; upgradeRecommended?: boolean; pluginVersion?: string;
  integrityStatus?: string; serverBrand?: string; minecraftVersion?: string;
  javaVersion?: string; loaderName?: string; loaderVersion?: string; telemetry?: ServerBridgeTelemetry;
};
export type BridgeCommandType =
  'player.kick' | 'message.broadcast' | 'whitelist.add' | 'whitelist.remove' |
  'whitelist.enable' | 'whitelist.disable' | 'ban.add' | 'ban.remove' |
  'server.save' | 'server.maintenance' | 'server.drain' | 'server.shutdown' | 'server.console';
export type ServerBridgeCommand = {
  id: string; serverId: string; runtimeId: string; runtimeEpoch: number; type: BridgeCommandType;
  status: string; idempotencyKey: string; attempt: number; deliverySequence: number;
  requestedBy?: string; payload?: Record<string, string>; result?: Record<string, string>;
  error?: string; createdAt: string; updatedAt: string; expiresAt: string; completedAt?: string;
};
export type BridgeOverview = {
  generatedAt?: string; release?: string; protocol?: { version?: number; status?: string; frozen?: boolean; featureDigest?: string; v2Mode?: string };
  nodes: ServerBridgeNode[]; control: ServerBridgeCommand[];
  metrics?: { nodesTotal?: number; nodesFresh?: number; nodesStale?: number; controlStatus?: Record<string, number> };
  topology?: Array<Record<string, unknown>>; audit?: Array<Record<string, unknown>>;
};
export type BridgeCommandRequest = { serverId: string; type: BridgeCommandType; payload: Record<string, string>; idempotencyKey: string };

export class ServerBridgeClient {
  private readonly baseUrl: string;
  private readonly token: string;
  constructor(baseUrl: string, token: string) { this.baseUrl = baseUrl; this.token = token; }
  overview(projectId: string): Promise<BridgeOverview> {
    if (!projectId) throw new Error('Выберите проект');
    return requestJSON(this.baseUrl, `/api/v1/server-bridge/projects/${encodeURIComponent(projectId)}/overview`, this.token);
  }
  async send(request: BridgeCommandRequest): Promise<{ command: ServerBridgeCommand; status: string; idempotentReplay: boolean }> {
    return requestJSON(this.baseUrl, `/api/v1/server-bridge/servers/${encodeURIComponent(request.serverId)}/control`, this.token, {
      method: 'POST', headers: { 'Idempotency-Key': request.idempotencyKey },
      body: JSON.stringify({ type: request.type, payload: request.payload, idempotencyKey: request.idempotencyKey }),
    });
  }
  async command(serverId: string, commandId: string): Promise<ServerBridgeCommand> {
    const response = await requestJSON<{ command: ServerBridgeCommand }>(this.baseUrl,
      `/api/v1/server-bridge/servers/${encodeURIComponent(serverId)}/control/${encodeURIComponent(commandId)}`, this.token);
    return response.command;
  }
}

export type BridgeLifecycle = 'queued' | 'dispatched' | 'delivered' | 'executed' | 'failed' | 'indeterminate';
export function commandLifecycle(raw: string): { lifecycle: BridgeLifecycle; label: string; terminal: boolean; deliveryConfirmed: boolean } {
  switch (raw.toLowerCase()) {
    case 'pending': return { lifecycle: 'queued', label: 'В очереди (queued)', terminal: false, deliveryConfirmed: false };
    case 'leased': return { lifecycle: 'dispatched', label: 'Передано на обработку (dispatched, ACK ещё нет)', terminal: false, deliveryConfirmed: false };
    case 'delivered': return { lifecycle: 'delivered', label: 'Доставлено (ожидается исполнение)', terminal: false, deliveryConfirmed: true };
    case 'succeeded': return { lifecycle: 'executed', label: 'Исполнено (Bridge ACK)', terminal: true, deliveryConfirmed: true };
    case 'failed': return { lifecycle: 'failed', label: 'Ошибка исполнения (Bridge ACK)', terminal: true, deliveryConfirmed: true };
    case 'unsupported': return { lifecycle: 'failed', label: 'Команда не поддерживается (Bridge ACK)', terminal: true, deliveryConfirmed: true };
    case 'expired': return { lifecycle: 'indeterminate', label: 'Срок команды истёк; выполнение не подтверждено', terminal: true, deliveryConfirmed: false };
    case 'indeterminate': return { lifecycle: 'indeterminate', label: 'Результат неопределён', terminal: true, deliveryConfirmed: false };
    default: return { lifecycle: 'indeterminate', label: `Неизвестный статус: ${raw || 'отсутствует'}`, terminal: false, deliveryConfirmed: false };
  }
}

export function telemetryState(node: ServerBridgeNode, now = Date.now()): { state: 'fresh' | 'stale' | 'unknown'; reason: string; ageSeconds: number | null } {
  const t = node.telemetry;
  if (!t || !Number.isFinite(t.sampledAtUnixMillis) || !t.sampledAtUnixMillis) return { state: 'unknown', reason: 'Telemetry ещё не получена', ageSeconds: null };
  const age = now - t.sampledAtUnixMillis;
  if (age < -30_000) return { state: 'unknown', reason: 'Время узла отличается от Backend/браузера', ageSeconds: null };
  const seconds = Math.max(0, Math.floor(age / 1000));
  if (!node.fresh || age > 120_000 || t.runtimeId !== node.runtimeId || t.runtimeEpoch !== node.runtimeEpoch) {
    return { state: 'stale', reason: 'Снимок устарел или относится к другому runtime', ageSeconds: seconds };
  }
  return { state: 'fresh', reason: 'Показатели актуальны', ageSeconds: seconds };
}
export function canControlNode(node: ServerBridgeNode, now = Date.now()): boolean {
  const beat = Date.parse(node.lastHeartbeatAt ?? '');
  return node.status === 'active' && node.fresh === true && Number.isFinite(beat) &&
    beat <= now + 30_000 && now - beat < 120_000 && node.protocolVersion === 3 &&
    (node.runtimeEpoch ?? 0) > 0 && /^[a-f0-9]{64}$/i.test(node.runtimeId ?? '');
}

const username = /^[A-Za-z0-9_]{3,16}$/;
const consoleAllowlist = new Set(['say', 'list', 'whitelist', 'ban', 'ban-ip', 'pardon', 'pardon-ip', 'save-all', 'save-off', 'save-on', 'kick', 'time', 'weather', 'difficulty', 'gamerule', 'title', 'tellraw']);
/** Client-side validation for operator feedback. The Backend validates again authoritatively. */
export function buildControlPayload(type: BridgeCommandType, fields: { username: string; reason: string; message: string; enabled: boolean; command: string }): Record<string, string> {
  const reason = fields.reason.trim();
  switch (type) {
    case 'player.kick': case 'whitelist.add': case 'whitelist.remove': case 'ban.add': case 'ban.remove':
      if (!username.test(fields.username.trim())) throw new Error('Имя игрока: 3–16 латинских символов, цифр или _');
      if (reason.length > 1024) throw new Error('Причина не должна превышать 1024 символа');
      return { username: fields.username.trim(), ...(reason && ['player.kick', 'ban.add'].includes(type) ? { reason } : {}) };
    case 'message.broadcast': {
      const message = fields.message.trim();
      if (!message || message.length > 1024) throw new Error('Текст сообщения: от 1 до 1024 символов');
      return { message };
    }
    case 'server.maintenance': case 'server.drain':
      if (reason.length > 1024) throw new Error('Причина не должна превышать 1024 символа');
      return { enabled: String(fields.enabled), ...(reason ? { reason } : {}) };
    case 'server.shutdown': return reason ? { reason } : {};
    case 'server.console': {
      const command = fields.command.trim();
      if (!command || command.length > 512 || /[\r\n\0]/.test(command)) throw new Error('Введите однострочную команду до 512 символов');
      const root = command.replace(/^\//, '').split(/\s+/)[0]?.toLowerCase();
      if (!consoleAllowlist.has(root)) throw new Error('Команда отсутствует в разрешённом списке ServerBridge');
      return { command };
    }
    default: return {};
  }
}
