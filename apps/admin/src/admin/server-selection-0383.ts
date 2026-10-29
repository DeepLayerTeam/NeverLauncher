import type { ServerBridgeNode } from '../api/serverbridge.ts';
import { canControlNode, telemetryState } from '../api/serverbridge.ts';

/** Backend-scoped inventory is the only source of node/profile membership. */
export function nodeForContext0383(nodes: readonly ServerBridgeNode[], projectId: string, serverId?: string): ServerBridgeNode | null {
  if (!serverId) return null;
  return nodes.find(n => n.projectId === projectId && n.id === serverId) ?? null;
}
export function profileNodes0383(nodes: readonly ServerBridgeNode[], projectId: string, profileId: string): ServerBridgeNode[] {
  return nodes.filter(n => n.projectId === projectId && n.profileId === profileId);
}
export type NodeState0383 = { status: 'available' | 'unavailable' | 'unknown'; label: string; heartbeat: 'fresh' | 'stale' | 'unknown'; telemetry: 'fresh' | 'stale' | 'unknown' };
/** Registration, signed heartbeat, control ACK, game join, and telemetry are different proofs. */
export function nodeState0383(n: ServerBridgeNode, snapshotFresh: boolean, now = Date.now()): NodeState0383 {
  const heartbeat = Date.parse(n.lastHeartbeatAt ?? '');
  const heartbeatFresh = snapshotFresh && n.fresh && Number.isFinite(heartbeat) && heartbeat <= now + 30_000 && now - heartbeat < 120_000;
  const telemetry = snapshotFresh ? telemetryState(n, now).state : 'unknown';
  if (!snapshotFresh) return { status:'unknown', label:'Нет свежего ответа Backend', heartbeat:'unknown', telemetry };
  if (!heartbeatFresh) return { status:'unavailable', label:'Heartbeat отсутствует или устарел', heartbeat: Number.isFinite(heartbeat) ? 'stale' : 'unknown', telemetry };
  if (!canControlNode(n, now)) return { status:'unavailable', label:'Узел не готов к управлению (status/protocol/runtime)', heartbeat:'fresh', telemetry };
  return { status:'available', label:'ServerBridge доступен (не подтверждает запуск Minecraft)', heartbeat:'fresh', telemetry };
}
