import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError } from '../api/client';
import { ResourceGrid } from '../components/ResourceGrid';
import { MetricCard } from '../components/primitives';
import { adminHref } from './route-links-0381';
import { nodeState0383 } from './server-selection-0383';
import { durableOwnerKey } from './owner-recovery-0388';
import { ServerBridgeClient, buildControlPayload, canControlNode, commandLifecycle, telemetryState,
  supportsControlCapability, networkStateFresh, parseCapacityDraft, parseBridgeEnrollment, type BridgeCommandRequest, type BridgeCommandType, type BridgeOverview, type ServerBridgeCommand, type ServerBridgeNode } from '../api/serverbridge';

type Props = { backendUrl: string; token: string; projectId: string; userId: string; selectedServerId?: string; selectedProfileId?: string; selectedChannelId?: string; onSelectServer?: (id: string) => void; allowedCommands: BridgeCommandType[]; allowEnrollment: boolean };
const actions: Array<{ type: BridgeCommandType; label: string; confirm?: boolean }> = [
  { type: 'player.kick', label: 'Отключить игрока', confirm: true },
  { type: 'message.broadcast', label: 'Сообщение всем игрокам' },
  { type: 'whitelist.add', label: 'Добавить в whitelist' }, { type: 'whitelist.remove', label: 'Убрать из whitelist', confirm: true },
  { type: 'whitelist.enable', label: 'Включить whitelist', confirm: true }, { type: 'whitelist.disable', label: 'Отключить whitelist', confirm: true },
  { type: 'ban.add', label: 'Заблокировать игрока', confirm: true }, { type: 'ban.remove', label: 'Снять блокировку' },
  { type: 'server.save', label: 'Сохранить мир' }, { type: 'server.maintenance', label: 'Режим обслуживания', confirm: true },
  { type: 'server.drain', label: 'Drain / запрет новых подключений', confirm: true },
  { type: 'server.shutdown', label: 'Остановить сервер', confirm: true }, { type: 'server.console', label: 'Разрешённая консольная команда', confirm: true },
];
const initialFields = { username: '', message: '', reason: '', enabled: true, command: '' };
// Session storage avoids persisting potentially sensitive console payloads on disk.
// Verified actor ID, not rotating session ID, is the scope across login refresh.
const pendingStorageKey = (projectId:string, backendUrl:string, userId:string) => durableOwnerKey(backendUrl,userId,projectId,'bridge')+'.pending';
const monitorStorageKey = (projectId:string, backendUrl:string, userId:string) => durableOwnerKey(backendUrl,userId,projectId,'bridge')+'.monitor';
const timeLabel = (iso?: string) => {
  const time = Date.parse(iso ?? '');
  return Number.isFinite(time) ? new Date(time).toLocaleString() : 'неизвестно';
};
const formatMetric = (value?: number | null) => typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('ru-RU', { maximumFractionDigits: 2 }) : '—';
const bytes = (value?: number) => Number.isFinite(value) && value !== undefined ? `${(value / (1024 * 1024)).toFixed(0)} МБ` : '—';
const lifecycleClass = (status: string) => status === 'succeeded' ? 'ok' : status === 'failed' || status === 'indeterminate' || status === 'unsupported' ? 'warn' : '';
const showProblem = (error: unknown) => {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Сессия истекла. Войдите заново.';
    if (error.status === 403) return `Недостаточно полномочий или требуется новый MFA step-up: ${error.message}`;
    if (error.status === 409) return `Конфликт состояния сервера или idempotency key: ${error.message}`;
  }
  return error instanceof Error ? error.message : 'Неизвестная ошибка';
};
const readPending = (projectId: string, backendUrl: string, userId: string): BridgeCommandRequest | null => {
  if (!projectId || !userId) return null;
  try {
    const data = JSON.parse(sessionStorage.getItem(pendingStorageKey(projectId, backendUrl, userId)) ?? 'null');
    if (typeof data?.serverId === 'string' && typeof data?.idempotencyKey === 'string' && typeof data?.type === 'string' && data.payload && typeof data.payload === 'object') return data as BridgeCommandRequest;
  } catch { /* stale browser state */ }
  return null;
};

export function ServerBridgeWorkspace({ backendUrl, token, projectId, userId, selectedServerId = '', selectedProfileId = '', selectedChannelId = '', onSelectServer, allowedCommands, allowEnrollment }: Props) {
  const canCommand = (kind: BridgeCommandType) => allowedCommands.includes(kind);
  const canControl = allowedCommands.length > 0;
  const canConsole = canCommand('server.console');
  const api = useMemo(() => new ServerBridgeClient(backendUrl, token), [backendUrl, token]);
  const [overview, setOverview] = useState<BridgeOverview | null>(null);
  const [selectedServer, setSelectedServer] = useState(selectedServerId);
  const [selectedCommand, setSelectedCommand] = useState<ServerBridgeCommand | null>(null);
  const [lastReadAt, setLastReadAt] = useState<number | null>(null);
  const [lastCommandReadAt, setLastCommandReadAt] = useState<number | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [enrollmentJSON, setEnrollmentJSON] = useState('');
  const [enrolling, setEnrolling] = useState(false);
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState<BridgeCommandType>('server.save');
  const [fields, setFields] = useState(initialFields);
  const [capacityDraft, setCapacityDraft] = useState('');
  const [capacityBusy, setCapacityBusy] = useState(false);
  // Update selection when RBAC or the signed runtime's capabilities change.
  useEffect(() => {
    const current = overview?.nodes.find(item => item.id === selectedServer);
    const possible = actions.filter(a => allowedCommands.includes(a.type) && (!current || supportsControlCapability(current, a.type)));
    if (!possible.some(a => a.type === kind) && possible.length > 0) setKind(possible[0].type);
  }, [kind, allowedCommands.join('|'), overview, selectedServer]);
  const [pending, setPending] = useState<BridgeCommandRequest | null>(() => readPending(projectId, backendUrl, userId));
  // A ref closes the double-click window before React commits busy=true.
  const submitInFlight = useRef(false);
  const [clock, setClock] = useState(Date.now());
  const nodes = overview?.nodes ?? [];
  const node = nodes.find(item => item.id === selectedServer) ?? null;
  const controls = (overview?.control ?? []).filter(item => !selectedServer || item.serverId === selectedServer);
  const network = (overview?.network ?? []).find(item => item.nodeId === selectedServer);
  const networkFresh = !!network && networkStateFresh(network, clock) && network.runtimeId === node?.runtimeId && network.runtimeEpoch === node?.runtimeEpoch;
  const projectRoutes = (overview?.topology ?? []).filter(edge => edge.sourceNodeId === selectedServer || edge.targetNodeId === selectedServer);
  const canTraffic = canCommand('server.drain') || canCommand('server.maintenance');
  useEffect(() => { setCapacityDraft(network?.operatorCapacityMax == null ? '' : String(network.operatorCapacityMax)); }, [selectedServer, network?.operatorCapacityRevision]);


  useEffect(() => { setOverview(null); setSelectedServer(selectedServerId); setSelectedCommand(null); setError(''); setPending(readPending(projectId, backendUrl, userId));
    const persisted = sessionStorage.getItem(monitorStorageKey(projectId, backendUrl, userId));
    if (persisted) {
      try {
        const { serverId, commandId } = JSON.parse(persisted);
        if (typeof serverId === 'string' && typeof commandId === 'string' && serverId && commandId)
          void api.command(serverId, commandId).then(c => {setSelectedServer(serverId);setSelectedCommand(c);setLastCommandReadAt(Date.now());}).catch(() => undefined);
      } catch { /* outdated monitor entry */ }
    }
  }, [api, backendUrl, token, projectId, userId]);
  useEffect(() => { setSelectedServer(selectedServerId); setSelectedCommand(null); }, [selectedServerId]);
  useEffect(() => {
    if (!projectId || !token) return;
    let alive = true;
    const refresh = async () => {
      try {
        const data = await api.overview(projectId);
        if (!alive) return;
        setOverview(data); setLastReadAt(Date.now()); setError('');
        setSelectedServer(old => data.nodes.some(n => n.id === old) ? old : (selectedServerId && data.nodes.some(n => n.id === selectedServerId) ? selectedServerId : ''));
      } catch (e) { if (alive) {setOverview(null);setLastReadAt(null);setError(`Не удалось обновить сведения ServerBridge: ${showProblem(e)}. Последний снимок нельзя считать актуальным.`);} }
    };
    void refresh();
    const id = window.setInterval(() => { if (!document.hidden) void refresh(); }, 15000);
    return () => { alive = false; window.clearInterval(id); };
  }, [api, projectId, token, selectedServerId]);
  useEffect(() => { const id = window.setInterval(() => setClock(Date.now()), 1000); return () => window.clearInterval(id); }, []);
  useEffect(() => {
    if (!selectedCommand || !token) return;
    const serverId = selectedCommand.serverId;
    const commandId = selectedCommand.id;
    let alive = true;
    const refresh = async () => {
      try {
        const result = await api.command(serverId, commandId);
        if (alive) { setSelectedCommand(result); setLastCommandReadAt(Date.now()); }
      } catch (e) { if (alive) setError(`Не удалось получить ACK команды ${commandId}: ${showProblem(e)}. Результат неизвестен.`); }
    };
    void refresh();
    if (commandLifecycle(selectedCommand.status).terminal) return () => { alive = false; };
    const id = window.setInterval(refresh, 3000);
    return () => { alive = false; window.clearInterval(id); };
  }, [api, selectedCommand?.id, selectedCommand?.serverId, selectedCommand?.status, token]);

  function persistPending(next: BridgeCommandRequest | null) {
    setPending(next);
    if (next) sessionStorage.setItem(pendingStorageKey(projectId, backendUrl, userId), JSON.stringify(next));
    else sessionStorage.removeItem(pendingStorageKey(projectId, backendUrl, userId));
  }
  async function submit(existing?: BridgeCommandRequest) {
    if (submitInFlight.current || busy) return;
    // Refuse to submit on stale overview or when a previous request has an
    // indeterminate outcome. The saved payload is the only safe retry.
    if (!node || !canControl || !canCommand(existing?.type ?? kind) || !supportsControlCapability(node, existing?.type ?? kind, clock) ||
        lastReadAt === null || clock - lastReadAt >= 45_000 ||
        (existing?.type === 'server.console' || (!existing && kind === 'server.console')) && !canConsole) return;
    const unresolved = readPending(projectId, backendUrl, userId);
    if (!existing && unresolved) { setPending(unresolved); setError('Сначала восстановите ранее отправленную команду.'); return; }
    setError(''); setMessage('');
    let request: BridgeCommandRequest;
    try {
      request = existing ?? { serverId: node.id, type: kind, payload: buildControlPayload(kind, fields), idempotencyKey: crypto.randomUUID() };
    } catch (e) { setError(showProblem(e)); return; }
    if (request.serverId !== node.id) { setError('Перейдите к серверу незавершённой операции.'); return; }
    if (existing && (!unresolved || JSON.stringify(existing) !== JSON.stringify(unresolved))) { setError('Повтор допустим только с неизменённой сохранённой командой.'); return; }
    if (!existing) {
      const effect = `${actions.find(a => a.type === kind)?.label} на сервере ${node.name || node.id} (${node.id})\n${Object.entries(request.payload).map(([k,v]) => `${k}: ${v}`).join('\n') || 'Без аргументов'}\n\nКоманда будет выполнена игровым сервером. Отмена после dispatch не гарантируется.`;
      if (!window.confirm(effect)) return;
      persistPending(request); // Save BEFORE network IO; retry uses exactly the same payload + key.
    }
    submitInFlight.current = true;
    setBusy(true);
    try {
      const response = await api.send(request);
      if (!response.command?.id) throw new Error('Backend не вернул ID управляющей команды');
      sessionStorage.setItem(monitorStorageKey(projectId, backendUrl, userId), JSON.stringify({serverId: response.command.serverId, commandId: response.command.id}));
      setSelectedCommand(response.command); setLastCommandReadAt(Date.now());
      setMessage(response.idempotentReplay ? 'Повтор запроса: возвращена ранее сохранённая команда.' : 'Команда поставлена в очередь. Ожидаем подтверждение от Bridge.');
      persistPending(null);
      const latest = await api.overview(projectId).catch(() => null);
      if (latest) { setOverview(latest); setLastReadAt(Date.now()); }
    } catch (e) { setError(`${showProblem(e)}. Повторите отправку с тем же ключом; новая команда не создаётся автоматически.`); }
    finally { submitInFlight.current = false; setBusy(false); }
  }
  async function enrollNode() {
    if (!allowEnrollment || enrolling || !projectId) return;
    setError(''); setMessage('');
    try {
      const request = parseBridgeEnrollment(enrollmentJSON, projectId);
      if (nodes.some(item => item.id === request.id)) throw new Error('Узел уже зарегистрирован. Ротация идентичности выполняется отдельно с phishing-resistant MFA.');
      if (!window.confirm(`Зарегистрировать ${request.id} (${request.kind}) в проекте ${projectId}?\nПубличный Ed25519 fingerprint: ${request.keyFingerprint}\nПриватный ключ должен остаться на хосте.`)) return;
      setEnrolling(true);
      const result = await api.register(request);
      if (result.server?.id !== request.id || result.server.keyFingerprint !== request.keyFingerprint) throw new Error('Backend вернул не ту идентичность; проверьте запись узла и аудит.');
      setEnrollmentJSON('');
      const fresh = await api.overview(projectId);
      setOverview(fresh); setLastReadAt(Date.now()); setSelectedServer(request.id); onSelectServer?.(request.id);
      setMessage(`Узел ${request.id} зарегистрирован. Запустите установленный адаптер и дождитесь свежего подписанного heartbeat; регистрация не подтверждает работоспособность.`);
    } catch (e) { setError(`Enrollment: ${showProblem(e)}. При потере HTTP-ответа проверьте список узлов перед повторением.`); }
    finally { setEnrolling(false); }
  }
  async function applyNetworkCapacity() {
    if (!node || !network || !canTraffic || capacityBusy || !networkFresh ||
        lastReadAt === null || Date.now() - lastReadAt >= 45_000 || pending) return;
    let limit: number | null;
    try { limit = parseCapacityDraft(capacityDraft); } catch (e) { setError(showProblem(e)); return; }
    if (limit === network.operatorCapacityMax) return;
    const label = limit === null ? 'Снять операторский лимит' : limit === 0 ? 'Закрыть приём новых игроков' : `Установить максимум ${limit} мест`;
    if (!window.confirm(`${label} для ${node.name || node.id}?\nСуществующие соединения не отключаются. Незавершённые handoff будут отозваны.`)) return;
    setCapacityBusy(true); setError(''); setMessage('');
    try {
      await api.setCapacity(node.id, network, limit);
      const current = await api.overview(projectId);
      setOverview(current); setLastReadAt(Date.now());
      setMessage('Операторский лимит применён в PostgreSQL и проверен обновлённым снимком.');
    } catch (e) {
      setError(`${showProblem(e)}. Если запрос оборвался, проверьте актуальную ревизию политики перед повторной отправкой.`);
    } finally { setCapacityBusy(false); }
  }
  if (!projectId) return <section className="card wide"><h2>ServerBridge</h2><p>Выберите доступный проект.</p></section>;
  const monitor = selectedCommand ? commandLifecycle(selectedCommand.status) : null;
  const monitorFresh = lastCommandReadAt !== null && clock - lastCommandReadAt < 15_000;
  const snapshotFresh = lastReadAt !== null && clock - lastReadAt < 45_000;
  const usable = !!node && canControlNode(node, clock) && snapshotFresh;
  const selectedNodeState = node ? nodeState0383(node,snapshotFresh,clock) : null;
  const boundToProfile = !!node && !!node.profileId && node.profileId===selectedProfileId;
  const t = node?.telemetry;
  const tele = node ? telemetryState(node, clock) : null;
  const playerKinds = new Set<BridgeCommandType>(['player.kick','whitelist.add','whitelist.remove','ban.add','ban.remove']);
  return <section className="card wide bridgeWorkspace">
    <header className="bridgeHero"><div><h2>ServerBridge Operations</h2><p className="muted">Проект <code>{projectId}</code> · Protocol v3 frozen · данные обновляются каждые 15 секунд</p></div><span className={`badge ${snapshotFresh && !error ? 'ok' : 'warn'}`}>{snapshotFresh && !error ? 'снимок актуален' : 'снимок устарел / неизвестен'}</span></header>
    {error && <p className="error" role="alert">{error}</p>}{message && <p className="success" role="status">{message}</p>}
    <details className="advanced" open={nodes.length === 0 && allowEnrollment}>
      <summary>Подключить узел ServerBridge (проверенная регистрация)</summary>
      <p className="muted">На хосте игрового сервера выполните <code>nl server-bridge detect</code>, затем <code>nl server-bridge install --server-root &lt;path&gt; --artifact-dir &lt;certified-release&gt; --backend &lt;url&gt; --server-id &lt;id&gt; --project &lt;project&gt;</code>. Для установки необходим сертифицированный JAR. В панели используется только открытый <code>.neverlauncher/server-bridge/enrollment-request.json</code>, никогда не загружайте <code>node-identity.properties</code>.</p>
      {allowEnrollment ? <form onSubmit={e=>{e.preventDefault();void enrollNode();}}>
        <label className="field"><span>Содержимое enrollment-request.json (только public key)</span>
          <textarea value={enrollmentJSON} rows={7} maxLength={16384} autoComplete="off" spellCheck={false} onChange={e=>setEnrollmentJSON(e.target.value)} required placeholder="{ &quot;schemaVersion&quot;: &quot;1.0&quot;, &quot;id&quot;: ... }"/></label>
        <button type="submit" disabled={enrolling || !enrollmentJSON.trim() || !snapshotFresh}>{enrolling ? 'Регистрация…' : 'Зарегистрировать публичный ключ'}</button>
      </form> : <p className="bridgeAttention">Регистрация требует глобального settings:manage. Проектные разрешения не дают доступ к регистрации узлов.</p>}
      <p className="muted">После запуска выполните на хосте <code>nl server-bridge verify --server-root &lt;path&gt; --backend &lt;url&gt;</code> с административным токеном из защищённого окружения. Свежий heartbeat и версия/хеш проверяются отдельно от факта регистрации.</p>
    </details>
    {overview && <div className="bridgeMetricGrid"><MetricCard label="Серверы проекта" value={nodes.length}/><MetricCard label="Активные heartbeat" value={nodes.filter(n=>n.fresh).length}/><MetricCard label="Устаревшие / нет данных" value={nodes.filter(n=>!n.fresh).length}/><MetricCard label="v3" value={nodes.filter(n=>n.protocolVersion===3).length}/><MetricCard label="Требуется миграция" value={nodes.filter(n=>n.protocolMigrationRequired).length}/><MetricCard label="Контрольные команды" value={controls.length}/></div>}
    {!overview && !error && <p role="status">Загрузка серверов…</p>}
    {overview && nodes.length === 0 && <div className="emptyState"><h3>Серверов нет</h3><p>В проекте ещё не зарегистрировано ни одного узла ServerBridge.</p></div>}
    {selectedProfileId && <p role="status">Выбран профиль <strong>{selectedProfileId}</strong>. Узлы, привязанные к нему: {nodes.filter(n=>n.profileId===selectedProfileId).length}. Связь определяется сохранённым profileId регистрации, не выбранным в браузере каналом.</p>}
    <div className="bridgeNodeGrid">{nodes.map(n => {
      const state = telemetryState(n, clock);
      const fresh = n.fresh && Number.isFinite(Date.parse(n.lastHeartbeatAt ?? '')) && clock-Date.parse(n.lastHeartbeatAt ?? '') < 120000 && snapshotFresh;
      return <button key={n.id} type="button" aria-pressed={n.id===selectedServer} className={`bridgeNodeButton ${n.id===selectedServer?'selected':''}`} onClick={()=>{setSelectedServer(n.id);setSelectedCommand(null);onSelectServer?.(n.id);}}>
        <strong>{n.name || n.id}</strong><span>Профиль: {n.profileId || 'не привязан'}</span><span className={`badge ${fresh?'ok':'warn'}`}>{fresh?'heartbeat fresh':'heartbeat stale/unknown'}</span>
        <span>{n.serverBrand || n.loaderName || n.kind || 'Minecraft'} · {n.minecraftVersion || 'версия неизвестна'}</span>
        <span>Players: {state.state==='fresh'?`${formatMetric(n.telemetry?.playersOnline)} / ${formatMetric(n.telemetry?.playersMax)}`:'неизвестно (telemetry stale)'}</span>
        <small>Protocol {n.protocolVersion || 'unknown'} · {state.state==='fresh'?'Telemetry fresh':state.reason}</small>
      </button>;
    })}</div>
    {node && <div className="bridgeSection" aria-label="Контекст сервера"><h3>Профиль и канал выпуска</h3>
      <p>Сервер зарегистрирован в проекте <strong>{node.projectId}</strong> для профиля <strong>{node.profileId || 'не задан'}</strong>. 
      Канал <strong>{selectedChannelId || 'не выбран'}</strong> — контекст подготовки релиза, а не подтверждённая конфигурация игрового узла.</p>
      <p role="status">{selectedNodeState?.label || 'Нет данных'}; heartbeat: {selectedNodeState?.heartbeat || 'unknown'}; telemetry: {selectedNodeState?.telemetry || 'unknown'}.</p>
      {node.profileId && !boundToProfile && <p className="bridgeAttention">Выберите профиль узла через список серверов. Нельзя выпускать сборку для другого профиля.</p>}
      {boundToProfile && selectedChannelId && <a href={adminHref('release-workspace',{projectId,profileId:node.profileId,channelId:selectedChannelId,serverId:node.id})}>Подготовить выпуск профиля {node.profileId} в канал {selectedChannelId}</a>}
      {boundToProfile && !selectedChannelId && <p>Выберите существующий канал в навигации проекта для перехода в мастер релизов.</p>}
    </div>}
    {node && <div className="bridgeColumns">
      <article className="bridgeSection"><h3>{node.name || node.id} · Runtime</h3>
        <dl className="bridgeFacts"><dt>Heartbeat</dt><dd>{timeLabel(node.lastHeartbeatAt)} · {usable?'active':'stale / unavailable'}</dd>
          <dt>Состояние</dt><dd>{node.status} · {node.runtimeTransition || 'переход неизвестен'}</dd>
          <dt>Protocol</dt><dd>v{node.protocolVersion} · {node.protocolMode || 'unknown'} · {node.protocolMigrationRequired?'нужна миграция':'migration n/a'}</dd>
          <dt>Plugin / integrity</dt><dd>{node.pluginVersion || '—'} · {node.integrityStatus || 'unknown'} {node.upgradeRecommended?' · upgrade recommended':''}</dd>
          <dt>Runtime ID</dt><dd><code>{node.runtimeId || 'неизвестен'}</code></dd>
          <dt>Runtime epoch</dt><dd>{node.runtimeEpoch || 'неизвестно'}</dd>
          <dt>Host / Java</dt><dd>{node.hostname || '—'} · {node.javaVersion || '—'}</dd>
          <dt>Loader</dt><dd>{node.loaderName || '—'} {node.loaderVersion || ''}</dd>
          <dt>Adapter capabilities</dt><dd>{node.runtimeCapabilities?.filter(c=>c.startsWith('adapter.')).length ?? 0} заявлено узлом; последнее подписанное runtime-состояние: {timeLabel(node.runtimeLastSeenAt)}. Это не сертификат Minecraft E2E.</dd>
          <dt>Login gate</dt><dd>{node.kind === 'vanilla' ? 'Нет: sidecar/RCON не перехватывает вход до логина' : node.runtimeCapabilities?.includes('adapter.auth.login-gate') ? 'Заявлен адаптером (runtime E2E отдельно)' : 'Не подтверждён'}</dd>
          <dt>Maintenance / drain</dt><dd>{networkFresh ? `Подписанный routing: ${network?.state}; admission: ${network?.reason}` : "Не подтверждено актуальным routing snapshot"}. ACK команд проверяйте отдельно.</dd></dl>
      </article>
      <article className="bridgeSection"><h3>Телеметрия и игроки</h3>
        <span className={`badge ${tele?.state==='fresh' && snapshotFresh?'ok':'warn'}`}>{tele?.state === 'fresh' && snapshotFresh ? `Fresh · ${tele.ageSeconds} сек` : tele?.reason || 'нет данных'}</span>
        <dl className="bridgeFacts"><dt>Online / max</dt><dd>{tele?.state==='fresh' && snapshotFresh ? `${formatMetric(t?.playersOnline)} / ${formatMetric(t?.playersMax)}` : 'неизвестно'}</dd>
          <dt>TPS / MSPT</dt><dd>{tele?.state==='fresh' && snapshotFresh ? `${formatMetric(t?.tps)} / ${formatMetric(t?.mspt)}` : 'неизвестно'}</dd>
          <dt>Tick health</dt><dd>{tele?.state==='fresh' && snapshotFresh ? t?.tickHealth || 'неизвестно' : 'неизвестно'}</dd>
          <dt>Heap</dt><dd>{tele?.state==='fresh' && snapshotFresh ? `${bytes(t?.heapUsedBytes)} / ${bytes(t?.heapMaxBytes)}` : 'неизвестно'}</dd>
          <dt>Worlds / chunks</dt><dd>{tele?.state==='fresh' && snapshotFresh ? `${formatMetric(t?.loadedWorlds)} / ${formatMetric(t?.loadedChunks)}` : 'неизвестно'}</dd>
          <dt>Снимок</dt><dd>{t?.sampledAtUnixMillis ? new Date(t.sampledAtUnixMillis).toLocaleString() : 'неизвестно'}</dd></dl>
        <p className="muted">Protocol v3 сообщает число игроков, а не список ников. Для kick/ban имя вводится вручную.</p>
      </article>
    </div>}
    <section className="bridgeSection" aria-label="Панель серверной сети"><h3>Сеть · Topology & Admission</h3>
      <p className="muted">PostgreSQL: подписанное состояние узлов + независимая политика доступа оператора. Routing обновляется узлами, журнал команд отдельно подтверждает их выполнение.</p>
      <div className="bridgeMetricGrid"><MetricCard label="Доступные маршруты" value={(overview?.topology ?? []).filter(e=>e.status==='active').length}/>
        <MetricCard label="Недоступные маршруты" value={(overview?.topology ?? []).filter(e=>e.status!=='active').length}/>
        <MetricCard label="Узлы с актуальным routing" value={(overview?.network ?? []).filter(n=>networkStateFresh(n,clock)).length}/>
        <MetricCard label="Приём закрыт политикой" value={(overview?.network ?? []).filter(n=>n.operatorCapacityMax===0).length}/></div>
      {node && <><h4>Admission для {node.name || node.id}</h4>
        {!network && <p className="bridgeAttention">PostgreSQL routing state отсутствует; управление capacity недоступно.</p>}
        {network && <><dl className="bridgeFacts">
          <dt>Источник / свежесть</dt><dd>{network.source} · {networkFresh && snapshotFresh?'актуально':'stale/не подтверждено'} · наблюдение {timeLabel(network.observedAt ?? undefined)}</dd>
          <dt>Runtime</dt><dd><code>{network.runtimeId}</code> · epoch {network.runtimeEpoch} · routing revision {network.routingRevision}</dd>
          <dt>Готовность маршрута</dt><dd><span className={`badge ${networkFresh && network.routable ? 'ok':'warn'}`}>{networkFresh && network.routable?'принимает новых игроков':network.reason}</span> · узел {network.state} / {network.health}</dd>
          <dt>Загрузка / резерв</dt><dd>{network.playersOnline} игроков · {network.reservedSlots} handoff reservations · свободно {network.availableSlots === -1?'без лимита':network.availableSlots}</dd>
          <dt>Capacity</dt><dd>Подписанный лимит {network.capacityMax===0?'без лимита':network.capacityMax} · операторский {network.operatorCapacityMax===null?'не задан':network.operatorCapacityMax} · эффективный {network.effectiveCapacityMax===0 && network.operatorCapacityMax===null?'без лимита':network.effectiveCapacityMax}</dd>
          <dt>Политика</dt><dd>revision {network.operatorCapacityRevision} · {timeLabel(network.operatorUpdatedAt ?? undefined)} · {network.operatorUpdatedBy || 'системное значение'}</dd></dl>
          {canTraffic && ['bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge'].includes(node.kind ?? '') && <form onSubmit={e=>{e.preventDefault();void applyNetworkCapacity();}}>
            <label className="field"><span>Лимит новых подключений: пусто — без ограничения оператора, 0 — запрет, 1–1000000 — максимум</span>
              <input type="number" min={0} max={1000000} step={1} value={capacityDraft} disabled={capacityBusy || !networkFresh || !snapshotFresh || !!pending} onChange={e=>setCapacityDraft(e.target.value)} placeholder="Не ограничивать"/></label>
            <div className="buttonRow"><button type="submit" disabled={capacityBusy || !networkFresh || !snapshotFresh || !!pending || !canControlNode(node,clock)}>{capacityBusy?'Применяется…':'Применить лимит в сети'}</button></div>
          </form>}
          {canTraffic && <div className="buttonRow">
            <button type="button" disabled={!canCommand('server.drain') || !supportsControlCapability(node,'server.drain',clock)} onClick={()=>{setKind('server.drain');setFields(f=>({...f,enabled:true}));}}>Подготовить drain</button>
            <button type="button" disabled={!canCommand('server.maintenance') || !supportsControlCapability(node,'server.maintenance',clock)} onClick={()=>{setKind('server.maintenance');setFields(f=>({...f,enabled:true}));}}>Подготовить maintenance</button>
            <button type="button" disabled={!canCommand('server.drain') || !supportsControlCapability(node,'server.drain',clock)} onClick={()=>{setKind('server.drain');setFields(f=>({...f,enabled:false}));}}>Подготовить возврат из drain</button>
          </div>}
          <p className="muted">Команды drain/maintenance исполняются через форму ниже с MFA, idempotency и Bridge ACK. Capacity применяется непосредственно к маршрутам и handoff через PostgreSQL, не меняет max-players в Minecraft и не отключает существующих игроков.</p>
        </>}
        <h4>Маршруты proxy → backend</h4>
        {projectRoutes.length === 0 ? <p className="muted">Для узла нет доступных связей или наблюдений topology.</p> : <div className="bridgeNetworkTable"><table><thead><tr><th>Proxy</th><th>Backend</th><th>Маршрут</th><th>Игроки / ёмкость</th><th>Наблюдение</th></tr></thead><tbody>
          {projectRoutes.map(e=><tr key={`${e.sourceNodeId}:${e.targetNodeId}`}><td>{nodes.find(n=>n.id===e.sourceNodeId)?.name || e.sourceNodeId}</td>
            <td>{e.backendName || e.targetNodeId}</td><td><span className={`badge ${e.status==='active' && snapshotFresh?'ok':'warn'}`}>{snapshotFresh?e.status:'stale snapshot'}</span></td>
            <td>{e.targetPlayers??'—'} / {e.targetCapacity===0?'∞':e.targetCapacity??'—'}</td><td>{timeLabel(e.lastSeenAt)}</td></tr>)}</tbody></table></div>}
      </>}
    </section>
    {node && <section className="bridgeSection bridgeControls"><h3>Управление сервером и игроками</h3>
      {!canControl && <p className="bridgeAttention">Необходимы разрешения семейства <code>gameserver:*</code> для выбранного проекта.</p>}
      {!usable && <p className="bridgeAttention">Отправка отключена: heartbeat, runtime, Protocol v3 или снимок недоступны. Обновите Backend и соединение с сервером.</p>}
      {usable && !actions.some(a=>canCommand(a.type) && supportsControlCapability(node,a.type,clock)) && <p className="bridgeAttention">Нет разрешённых операций, подтверждённых свежими runtime capabilities этого адаптера.</p>}
      <form onSubmit={e=>{e.preventDefault();void submit();}}>
        <label className="field"><span>Действие</span><select value={kind} disabled={busy || !!pending} onChange={e=>setKind(e.target.value as BridgeCommandType)}>{actions.filter(a=>canCommand(a.type) && supportsControlCapability(node,a.type,clock)).map(a=><option value={a.type} key={a.type}>{a.label}</option>)}</select></label>
        {playerKinds.has(kind) && <label className="field"><span>Имя Minecraft-игрока</span><input required maxLength={16} pattern="[A-Za-z0-9_]{3,16}" autoComplete="off" value={fields.username} onChange={e=>setFields(f=>({...f,username:e.target.value}))}/></label>}
        {kind==='message.broadcast' && <label className="field"><span>Сообщение</span><textarea maxLength={1024} required rows={3} value={fields.message} onChange={e=>setFields(f=>({...f,message:e.target.value}))}/></label>}
        {['player.kick','ban.add','server.maintenance','server.drain','server.shutdown'].includes(kind) && <label className="field"><span>Причина (необязательно)</span><input maxLength={1024} value={fields.reason} onChange={e=>setFields(f=>({...f,reason:e.target.value}))}/></label>}
        {(kind==='server.maintenance'||kind==='server.drain') && <label className="check"><input type="checkbox" checked={fields.enabled} onChange={e=>setFields(f=>({...f,enabled:e.target.checked}))}/><span>{fields.enabled?'Включить':'Выключить'} {kind==='server.drain'?'drain':'maintenance'}</span></label>}
        {kind==='server.console' && canConsole && <label className="field"><span>Разрешённая команда (без shell)</span><input required maxLength={512} value={fields.command} onChange={e=>setFields(f=>({...f,command:e.target.value}))} placeholder="say Плановая перезагрузка" autoComplete="off"/></label>}
        <div className="buttonRow"><button disabled={!canCommand(kind) || !usable || !supportsControlCapability(node,kind,clock) || busy || !!pending} type="submit">{busy?'Отправка…':'Проверить эффект и отправить'}</button></div>
      </form>
      {pending && <div className="bridgePending"><p className="bridgeAttention">Запрос {pending.type} для {pending.serverId} не получил подтверждённого ответа. Идемпотентный ключ сохранён в этой сессии.</p><div className="buttonRow"><button disabled={busy || selectedServer!==pending.serverId || !usable || !canCommand(pending.type) || !supportsControlCapability(node,pending.type,clock)} onClick={()=>void submit(pending)}>Повторить с тем же ключом</button><button disabled={busy} onClick={()=>{if(window.confirm('Отказаться от восстановления? При неизвестном результате создание новой команды может повторить действие.'))persistPending(null);}}>Отказаться от восстановления</button></div></div>}
      <p className="muted">Каждая команда требует собственное право gameserver:*. Backend проверяет RBAC, MFA (fresh ≤ 5 минут), runtime identity и allowlist. Право broadcast не даёт доступа к shutdown, Backend или Host. Shell-доступ не используется.</p>
    </section>}
    {selectedCommand && <section className="bridgeSection" aria-live="polite"><h3>Монитор команды</h3><div className="bridgeHero"><strong><code>{selectedCommand.id}</code></strong><span className={`badge ${monitorFresh?lifecycleClass(selectedCommand.status):'warn'}`}>{monitorFresh?monitor?.label:'Статус устарел / неизвестен'}</span></div>
      <dl className="bridgeFacts"><dt>Команда</dt><dd>{selectedCommand.type}</dd><dt>Сервер / runtime</dt><dd>{selectedCommand.serverId} / epoch {selectedCommand.runtimeEpoch}</dd><dt>Попытка / sequence</dt><dd>{selectedCommand.attempt} / {selectedCommand.deliverySequence}</dd><dt>Доставка</dt><dd>{monitorFresh && monitor?.deliveryConfirmed?'подтверждена ответом Bridge':'не подтверждена; dispatch не равен delivery'}</dd><dt>Результат</dt><dd>{monitorFresh && monitor?.lifecycle==='executed'?'исполнено':monitorFresh?monitor?.label:'неизвестно'}</dd><dt>Обновлено</dt><dd>{timeLabel(selectedCommand.updatedAt)}</dd><dt>Ошибка</dt><dd>{selectedCommand.error || '—'}</dd></dl>
      {selectedCommand.result && Object.keys(selectedCommand.result).length > 0 && <details><summary>Результат, возвращённый Bridge</summary><dl className="bridgeFacts">{Object.entries(selectedCommand.result).map(([key,value])=><React.Fragment key={key}><dt>{key}</dt><dd>{value}</dd></React.Fragment>)}</dl></details>}
      <div className="buttonRow"><button onClick={()=>api.command(selectedCommand.serverId,selectedCommand.id).then(item=>{setSelectedCommand(item);setLastCommandReadAt(Date.now());}).catch(e=>setError(showProblem(e)))}>Обновить статус</button></div>
      {monitor?.lifecycle==='indeterminate' && <p className="bridgeAttention">Исход неизвестен. Не повторяйте команду новым ключом без проверки состояния Minecraft-сервера.</p>}
    </section>}
    <section className="bridgeSection"><h3>Журнал команд</h3>
      <ResourceGrid section="server-bridge" payload={{items:controls.map(c=>({...c,lifecycle:commandLifecycle(c.status).label}))}} selectedId={selectedCommand?.id} onSelect={row=>{const c=controls.find(item=>item.id===row.id);if(c){setSelectedCommand(c);setLastCommandReadAt(lastReadAt);}}} columns={[{field:'id',title:'Command ID'},{field:'serverId',title:'Сервер',facet:true},{field:'type',title:'Операция',facet:true},{field:'lifecycle',title:'Статус',facet:true},{field:'attempt',title:'Попытка'},{field:'updatedAt',title:'Время',datetime:true}]}/>
      <p className="muted">Journal: последние 100 команд Backend. pending = queued, leased = dispatched (не delivered); succeeded = executed после Bridge ACK; failed и indeterminate отображаются раздельно.</p>
    </section>
    <details className="advanced"><summary>Диагностика Protocol v3, topology и audit</summary><p className="muted">{overview?.protocol?.status || 'unknown'} · digest <code>{overview?.protocol?.featureDigest||'unknown'}</code> · frozen: {String(overview?.protocol?.frozen??'unknown')}</p><ResourceGrid section="server-bridge" payload={{items:overview?.topology||[]}}/><ResourceGrid section="audit" payload={{items:overview?.audit||[]}}/></details>
  </section>;
}
