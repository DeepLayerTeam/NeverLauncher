import { requestJSON } from './client.ts';

export type HostAction04111 = 'start' | 'stop' | 'restart';
export type HostOperation04111 = {
  id: string; serverId: string; action: HostAction04111; status: 'indeterminate' | 'accepted' | 'succeeded';
  requestedBy: string; idempotencyKey: string; remoteNodeId: string;
  baselineRuntimeId?: string; baselineRuntimeEpoch: number;
  hostBefore?: HostObservation04111; hostAfter?: HostObservation04111;
  remoteReceipt?: { action: string; state: string; error?: string };
  error?: string; createdAt: string; updatedAt: string;
};
export type HostObservation04111 = {
  nodeId: string;
  status: { configured: boolean; observedStatus: string; processAlive: boolean;
    supervisorAlive: boolean; sessionId: string; telemetry?: {
      processId?: number; processResidentBytes?: number;
      hostTotalMemoryBytes?: number; hostAvailableMemoryBytes?: number;
    } };
};
export type HostSnapshot04111 = {
  host: HostObservation04111; observedAt: string;
  bridge: { serverId: string; status: string; runtimeId: string; runtimeEpoch: number; lastHeartbeatAt: string };
};
export type HostResult04111 = {
  operation: HostOperation04111; idempotentReplay: boolean; hostState: string;
  bridge: HostSnapshot04111['bridge']; controlDomain: 'host-process';
};
export type HostPending04111 = { serverId: string; action: HostAction04111; idempotencyKey: string };

export function validHostPending04111(value: unknown): value is HostPending04111 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.serverId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(obj.serverId) &&
    ['start','stop','restart'].includes(String(obj.action)) && typeof obj.idempotencyKey === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/.test(obj.idempotencyKey);
}
export function hostOperationOutcome04111(op: HostOperation04111): { label: string; verified: boolean; unresolved: boolean } {
  if (op.status === 'succeeded') return { label: 'Подтверждено Backend по состоянию хоста и ServerBridge', verified: true, unresolved: false };
  if (op.status === 'accepted') return { label: 'Хост принял операцию, конечное состояние игры ещё не проверено', verified: false, unresolved: true };
  return { label: 'Исход неизвестен. Никаких новых действий до сверки', verified: false, unresolved: true };
}
export function hostSnapshotFresh04111(snapshot: HostSnapshot04111 | null, now = Date.now()): boolean {
  if (!snapshot) return false;
  const observed = Date.parse(snapshot.observedAt);
  if (!Number.isFinite(observed) || observed > now + 30000 || now - observed >= 20000) return false;
  const host = snapshot.host;
  if (!host?.nodeId || !host.status?.configured) return false;
  return true; // This is a live RemoteControl observation, NOT a game-ready verdict.
}
export function bridgeReady04111(snapshot: HostSnapshot04111 | null, now = Date.now()): boolean {
  if (!hostSnapshotFresh04111(snapshot, now)) return false;
  const bridge = snapshot!.bridge;
  const beat = Date.parse(bridge.lastHeartbeatAt);
  return bridge.status === 'active' && bridge.runtimeEpoch > 0 && /^[0-9a-f]{64}$/i.test(bridge.runtimeId) &&
    Number.isFinite(beat) && beat <= now + 30000 && now - beat < 90000;
}

export class HostOperationsClient04111 {
  private readonly backendUrl: string;
  private readonly token: string;
  constructor(backendUrl: string, token: string) { this.backendUrl=backendUrl; this.token=token; }
  private path(serverId: string) {
    if (!serverId) throw Error('Выберите сервер');
    return `/api/v1/server-bridge/servers/${encodeURIComponent(serverId)}/host`;
  }
  status(serverId: string): Promise<HostSnapshot04111> {
    return requestJSON(this.backendUrl, `${this.path(serverId)}/status`, this.token);
  }
  list(serverId: string): Promise<HostOperation04111[]> {
    return requestJSON<{items: HostOperation04111[]}>(this.backendUrl, `${this.path(serverId)}/operations`, this.token)
      .then(result => result.items);
  }
  create(pending: HostPending04111): Promise<HostResult04111> {
    if (!validHostPending04111(pending)) throw Error('Недействительная сохранённая операция');
    return requestJSON(this.backendUrl, `${this.path(pending.serverId)}/operations`, this.token, {
      method: 'POST', headers: {'Idempotency-Key': pending.idempotencyKey},
      body: JSON.stringify({ action: pending.action }),
    });
  }
  get(serverId: string, operationId: string, reconcile = false): Promise<HostResult04111> {
    if (!operationId) throw Error('Не выбран operation ID');
    return requestJSON(this.backendUrl, `${this.path(serverId)}/operations/${encodeURIComponent(operationId)}${reconcile ? '?refresh=1' : ''}`, this.token);
  }
}
