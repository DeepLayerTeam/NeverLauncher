import type { ServerBridgeNode } from '../api/serverbridge.ts';
import { canControlNode, telemetryState } from '../api/serverbridge.ts';

/** Список, ограниченный правами в Backend, — единственный источник членства узла в профиле. */
export function nodeForContext0383(nodes: readonly ServerBridgeNode[], projectId: string, serverId?: string): ServerBridgeNode | null {
  if (!serverId) return null;
  return nodes.find(n => n.projectId === projectId && n.id === serverId) ?? null;
}
export function profileNodes0383(nodes: readonly ServerBridgeNode[], projectId: string, profileId: string): ServerBridgeNode[] {
  return nodes.filter(n => n.projectId === projectId && n.profileId === profileId);
}
export type NodeState0383 = { status: 'available' | 'unavailable' | 'unknown'; label: string; heartbeat: 'fresh' | 'stale' | 'unknown'; telemetry: 'fresh' | 'stale' | 'unknown' };
/** Регистрация, подписанный heartbeat, подтверждение команды ACK, вход в игру и телеметрия представляют разные доказательства. */
export function nodeState0383(n: ServerBridgeNode, snapshotFresh: boolean, now = Date.now()): NodeState0383 {
  const heartbeat = Date.parse(n.lastHeartbeatAt ?? '');
  const heartbeatFresh = snapshotFresh && n.fresh && Number.isFinite(heartbeat) && heartbeat <= now + 30_000 && now - heartbeat < 120_000;
  const telemetry = snapshotFresh ? telemetryState(n, now).state : 'unknown';
  if (!snapshotFresh) return { status:'unknown', label:'Нет актуального ответа серверной части', heartbeat:'unknown', telemetry };
  if (!heartbeatFresh) return { status:'unavailable', label:'Сигнал состояния отсутствует или устарел', heartbeat: Number.isFinite(heartbeat) ? 'stale' : 'unknown', telemetry };
  if (!canControlNode(n, now)) return { status:'unavailable', label:'Узел не готов к управлению (статус, протокол или среда выполнения)', heartbeat:'fresh', telemetry };
  return { status:'available', label:'ServerBridge доступен (не подтверждает запуск Minecraft)', heartbeat:'fresh', telemetry };
}
