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
  runtimeCapabilities?: string[]; runtimeLastSeenAt?: string;
};
export type BridgeCommandType =
  'player.kick' | 'message.broadcast' | 'whitelist.add' | 'whitelist.remove' |
  'whitelist.enable' | 'whitelist.disable' | 'ban.add' | 'ban.remove' |
  'server.save' | 'server.maintenance' | 'server.drain' | 'server.shutdown' | 'server.console';
// UI visibility mirrors the API's closed, server-authoritative command policy.
// In particular, a game broadcast can NEVER grant backend restart or host shell.
export const gameCommandPermissions: Record<BridgeCommandType, string> = {
  'player.kick': 'gameserver:moderate',
  'message.broadcast': 'gameserver:broadcast',
  'whitelist.add': 'gameserver:moderate', 'whitelist.remove': 'gameserver:moderate',
  'whitelist.enable': 'gameserver:moderate', 'whitelist.disable': 'gameserver:moderate',
  'ban.add': 'gameserver:moderate', 'ban.remove': 'gameserver:moderate',
  'server.save': 'gameserver:save', 'server.maintenance': 'gameserver:traffic',
  'server.drain': 'gameserver:traffic', 'server.shutdown': 'gameserver:shutdown',
  'server.console': 'gameserver:console',
};
export function gameCommandPermission(kind: BridgeCommandType): string { return gameCommandPermissions[kind]; }

// This describes an observed, node-signed capability, NOT an E2E certificate.
const commandAdapterCapability: Record<BridgeCommandType, string> = {
  'player.kick': 'adapter.control.kick', 'message.broadcast': 'adapter.control.broadcast',
  'whitelist.add': 'adapter.control.whitelist', 'whitelist.remove': 'adapter.control.whitelist',
  'whitelist.enable': 'adapter.control.whitelist', 'whitelist.disable': 'adapter.control.whitelist',
  'ban.add': 'adapter.control.ban', 'ban.remove': 'adapter.control.ban',
  'server.save': 'adapter.control.save', 'server.maintenance': 'adapter.control.maintenance',
  'server.drain': 'adapter.control.drain', 'server.shutdown': 'adapter.control.shutdown',
  'server.console': 'adapter.control.console',
};
export function supportsControlCapability(node: ServerBridgeNode, kind: BridgeCommandType, now = Date.now()): boolean {
  const seen = Date.parse(node.runtimeLastSeenAt ?? '');
  if (!Number.isFinite(seen) || seen > now + 120_000 || now - seen > 90_000) return false;
  if (!canControlNode(node, now)) return false;
  return node.runtimeCapabilities?.includes(commandAdapterCapability[kind]) === true;
}

export type ServerBridgeCommand = {
  id: string; serverId: string; runtimeId: string; runtimeEpoch: number; type: BridgeCommandType;
  status: string; idempotencyKey: string; attempt: number; deliverySequence: number;
  requestedBy?: string; payload?: Record<string, string>; result?: Record<string, string>;
  error?: string; createdAt: string; updatedAt: string; expiresAt: string; completedAt?: string;
};
export type BridgeNetworkState = {
  nodeId: string; runtimeId: string; runtimeEpoch: number; state: string; health: string;
  acceptingConnections: boolean; playersOnline: number; capacityMax: number;
  operatorCapacityMax: number | null; operatorCapacityRevision: number;
  effectiveCapacityMax: number; availableSlots: number; reservedSlots: number;
  routable: boolean; reason: string; routingRevision: number;
  observedAt?: string | null; lastHeartbeatAt?: string | null;
  operatorUpdatedAt?: string | null; operatorUpdatedBy?: string; source: string;
};
export type BridgeTopologyEdge = {
  sourceNodeId: string; targetNodeId: string; backendName: string; projectId: string;
  status: string; sourceHealth?: string; targetHealth?: string; targetState?: string;
  targetPlayers?: number; targetCapacity?: number; acceptingConnections: boolean;
  targetRuntimeId?: string; targetRuntimeEpoch?: number; routingRevision?: number;
  lastSeenAt?: string;
} & Record<string, unknown>;
export function networkStateFresh(state: BridgeNetworkState, now = Date.now()): boolean {
  const observed = Date.parse(state.observedAt ?? '');
  const heartbeat = Date.parse(state.lastHeartbeatAt ?? '');
  return Number.isFinite(observed) && Number.isFinite(heartbeat) &&
    observed <= now + 30_000 && heartbeat <= now + 30_000 &&
    now - observed < 90_000 && now - heartbeat < 90_000 &&
    state.routingRevision > 0 && /^[0-9a-f]{64}$/i.test(state.runtimeId) && state.runtimeEpoch > 0;
}
/** Blank removes an operator override; zero explicitly closes admission. */
export function parseCapacityDraft(input: string): number | null {
  if (!input.trim()) return null;
  if (!/^(0|[1-9][0-9]*)$/.test(input.trim())) throw new Error('Capacity: целое число 0–1000000 или пустое поле');
  const number = Number(input.trim());
  if (!Number.isSafeInteger(number) || number > 1_000_000) throw new Error('Capacity: диапазон 0–1000000');
  return number;
}
export type BridgeOverview = {
  generatedAt?: string; release?: string; protocol?: { version?: number; status?: string; frozen?: boolean; featureDigest?: string; v2Mode?: string };
  nodes: ServerBridgeNode[]; control: ServerBridgeCommand[];
  metrics?: { nodesTotal?: number; nodesFresh?: number; nodesStale?: number; controlStatus?: Record<string, number> };
  topology?: BridgeTopologyEdge[]; network?: BridgeNetworkState[]; audit?: Array<Record<string, unknown>>;
};
export type BridgeCommandRequest = { serverId: string; type: BridgeCommandType; payload: Record<string, string>; idempotencyKey: string };

export type BridgeEnrollmentRequest = {
  schemaVersion: string; id: string; name: string; kind: string; projectId: string; profileId: string;
  keyAlgorithm: 'ed25519'; publicKey: string; keyFingerprint: string; backendUrl: string;
  artifactFile: string; artifactSha256: string;
};
/** Verify the exported public request, not a private-key file. Backend revalidates everything. */
export function parseBridgeEnrollment(input: string, projectId: string): BridgeEnrollmentRequest {
  if (input.length > 16_384) throw new Error('Слишком большой enrollment request');
  const raw: unknown = JSON.parse(input);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Неверный enrollment JSON');
  const request = raw as Record<string, unknown>;
  const fields = ['id','name','kind','projectId','profileId','keyAlgorithm','publicKey','keyFingerprint','backendUrl','artifactFile','artifactSha256'];
  if (fields.some(field => typeof request[field] !== 'string')) throw new Error('Enrollment request не содержит обязательные поля');
  if (Object.keys(request).some(field => /private|secret|token|password/i.test(field))) throw new Error('Не загружайте приватные ключи или токены');
  if (request.projectId !== projectId) throw new Error('Проект в enrollment request не соответствует выбранному проекту');
  if (request.keyAlgorithm !== 'ed25519' || !/^[0-9a-f]{64}$/i.test(String(request.keyFingerprint)) || !/^[0-9a-f]{64}$/i.test(String(request.artifactSha256))) throw new Error('Неверная криптографическая идентичность или SHA-256');
  if (!/^[A-Za-z0-9_-]{43}$/.test(String(request.publicKey))) throw new Error('Неверный формат публичного ключа Ed25519');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(String(request.id)) || !String(request.kind).trim()) throw new Error('Неверный сервер или тип адаптера');
  return request as BridgeEnrollmentRequest;
}

export class ServerBridgeClient {
  private readonly baseUrl: string;
  private readonly token: string;
  constructor(baseUrl: string, token: string) { this.baseUrl = baseUrl; this.token = token; }
  register(request: BridgeEnrollmentRequest): Promise<{ status: string; server: { id: string; keyFingerprint: string } }> {
    return requestJSON(this.baseUrl, '/api/v1/server-bridge/servers/register', this.token, {
      method: 'POST', body: JSON.stringify({
        id: request.id, name: request.name, kind: request.kind, projectId: request.projectId,
        profileId: request.profileId, keyAlgorithm: 'ed25519', publicKey: request.publicKey,
      }),
    });
  }
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
  async setCapacity(serverId: string, state: BridgeNetworkState, capacityLimit: number | null): Promise<{ nodeId: string; operatorCapacityMax: number | null; operatorCapacityRevision: number; status: string }> {
    return requestJSON(this.baseUrl, `/api/v1/server-bridge/servers/${encodeURIComponent(serverId)}/network-capacity`, this.token, {
      method: 'PUT', body: JSON.stringify({ capacityLimit, runtimeId: state.runtimeId,
        runtimeEpoch: state.runtimeEpoch, expectedRevision: state.operatorCapacityRevision }),
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
