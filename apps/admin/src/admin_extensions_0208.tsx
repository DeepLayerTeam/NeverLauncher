import React, { useEffect, useMemo, useRef, useState } from 'react';

const ADMIN_PROTOCOL = 'neverextensions.admin-rpc.v1';
const EXTENSION_API_VERSION = '1.0';

type Envelope<T> = { data?: T; error?: { message?: string } };
export type AdminPage = { id: string; title: string; description?: string };
export type AdminNavigation = { id: string; label: string; pageId: string; order?: number };
export type AdminWidget = { id: string; title: string; pageId: string; height?: number };
export type AdminAction = { id: string; label: string; pageId: string; placement?: 'toolbar' | 'dashboard' };
export type AdminContributions = { pages?: AdminPage[]; navigation?: AdminNavigation[]; dashboardWidgets?: AdminWidget[]; actions?: AdminAction[] };
export type RuntimeStatus = { state?: string; healthy?: boolean; pid?: number; restarts?: number; lastError?: string; memoryBytes?: number; processCount?: number; lastHeartbeatAt?: string };
export type AdminExtension = { extensionId: string; name: string; version: string; scope: string; scopeId?: string; generation: number; packageIdentity?: string; admin: AdminContributions; runtime?: RuntimeStatus; lastError?: string };
type Catalog = { protocol: string; extensionApiVersion: string; sandbox: string; items: AdminExtension[] };
type ManagerItem = { install?: Record<string, any>; manifest?: Record<string, any>; permissions?: Record<string, any>; runtime?: RuntimeStatus; logs?: Array<Record<string, any>> };
type ManagerData = { items?: ManagerItem[]; count?: number };

type Props = { backendUrl: string; token: string; mode?: 'workspace' | 'dashboard'; onError?: (message: string) => void };

async function api<T>(backendUrl: string, path: string, token: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined), Authorization: `Bearer ${token}` };
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${backendUrl.replace(/\/$/, '')}${path}`, { ...init, headers });
  const payload = await response.json().catch(() => ({})) as Envelope<T> | T;
  if (!response.ok) throw new Error((payload as Envelope<T>).error?.message ?? `${response.status} ${response.statusText}`);
  return ((payload as Envelope<T>).data ?? payload) as T;
}

function scopeQuery(ext: AdminExtension) {
  const p = new URLSearchParams({ scope: ext.scope });
  if (ext.scopeId) p.set('scopeId', ext.scopeId);
  return p.toString();
}

function AdminExtensionFrame({ backendUrl, token, extension, pageId, actionId, height = 560 }: { backendUrl: string; token: string; extension: AdminExtension; pageId: string; actionId?: string; height?: number }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const inflight = useRef(0);
  const [html, setHtml] = useState('');
  const [error, setError] = useState('');
  const scope = scopeQuery(extension);

  useEffect(() => {
    let cancelled = false;
    setHtml(''); setError('');
    api<{html: string; protocol: string; extensionApiVersion: string}>(backendUrl, `/api/v1/admin/extensions/${encodeURIComponent(extension.extensionId)}/ui?${scope}`, token)
      .then((data) => {
        if (data.protocol !== ADMIN_PROTOCOL || data.extensionApiVersion !== EXTENSION_API_VERSION) throw new Error('Несовпадение протокола/API расширения панели администратора');
        if (!cancelled) setHtml(data.html);
      })
      .catch((err: Error) => { if (!cancelled) setError(err.message); });
    return () => { cancelled = true; };
  }, [backendUrl, token, extension.extensionId, extension.version, extension.generation, scope]);

  useEffect(() => {
    const onMessage = async (event: MessageEvent) => {
      if (!frame.current || event.source !== frame.current.contentWindow) return;
      const message = event.data as any;
      if (!message || message.protocol !== ADMIN_PROTOCOL || message.type !== 'rpc.request' || typeof message.id !== 'string' || typeof message.method !== 'string') return;
      if (message.id.length > 160 || message.method.length > 64) return;
      const currentInflight = inflight.current ?? 0;
      if (currentInflight >= 32) { frame.current.contentWindow?.postMessage({ protocol: ADMIN_PROTOCOL, type: 'rpc.response', id: message.id, error: 'Превышен предел одновременных RPC-вызовов расширения панели администратора' }, '*'); return; }
      inflight.current = currentInflight + 1;
      try {
        const result = await api<any>(backendUrl, `/api/v1/admin/extensions/${encodeURIComponent(extension.extensionId)}/rpc?${scope}`, token, { method: 'POST', body: JSON.stringify({ protocol: ADMIN_PROTOCOL, id: message.id, method: message.method, params: message.params ?? {} }) });
        frame.current.contentWindow?.postMessage({ protocol: ADMIN_PROTOCOL, type: 'rpc.response', id: message.id, result: result.result, error: result.error }, '*');
      } catch (err) {
        frame.current.contentWindow?.postMessage({ protocol: ADMIN_PROTOCOL, type: 'rpc.response', id: message.id, error: err instanceof Error ? err.message : String(err) }, '*');
      } finally { inflight.current = Math.max(0, (inflight.current ?? 1) - 1); }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [backendUrl, token, extension.extensionId, scope]);

  const sendContext = () => {
    frame.current?.contentWindow?.postMessage({ protocol: ADMIN_PROTOCOL, type: 'host.context', context: { extensionId: extension.extensionId, version: extension.version, extensionApiVersion: EXTENSION_API_VERSION, scope: extension.scope, scopeId: extension.scopeId ?? '', pageId, actionId: actionId ?? '' } }, '*');
    if (actionId) frame.current?.contentWindow?.postMessage({ protocol: ADMIN_PROTOCOL, type: 'host.action', actionId, pageId }, '*');
  };

  if (error) return <div className="extensionFrameError">Extension UI: {error}</div>;
  if (!html) return <div className="extensionFrameLoading">Загрузка песочница расширение UI…</div>;
  return <iframe ref={frame} className="extensionFrame" title={`${extension.name}: ${pageId}`} sandbox="allow-scripts" referrerPolicy="no-referrer" srcDoc={html} onLoad={sendContext} style={{ height }} />;
}

function extensionKey(ext: AdminExtension) { return `${ext.scope}:${ext.scopeId ?? ''}:${ext.extensionId}`; }

export function AdminExtensions({ backendUrl, token, mode = 'workspace', onError }: Props) {
  const [catalog, setCatalog] = useState<AdminExtension[]>([]);
  const [manager, setManager] = useState<ManagerData>({});
  const [selected, setSelected] = useState<{key: string; pageId: string; actionId?: string} | null>(null);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');

  const refresh = async () => {
    if (!token) return;
    setLoading(true); setLocalError('');
    try {
      const data = await api<Catalog>(backendUrl, '/api/v1/admin/extensions/catalog', token);
      if (data.protocol !== ADMIN_PROTOCOL || data.extensionApiVersion !== EXTENSION_API_VERSION) throw new Error('Несовпадение протокола/API каталога расширений панели администратора');
      setCatalog(data.items ?? []);
      if (mode === 'workspace') {
        const m = await api<ManagerData>(backendUrl, '/api/v1/admin/extensions/manager', token).catch(() => ({ items: [] }));
        setManager(m);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err); setLocalError(message); onError?.(message);
    } finally { setLoading(false); }
  };

  useEffect(() => { refresh(); }, [backendUrl, token, mode]);

  const nav = useMemo(() => catalog.flatMap((ext) => (ext.admin.navigation ?? []).map((n) => ({ ext, nav: n }))).sort((a,b) => (a.nav.order ?? 0) - (b.nav.order ?? 0) || a.nav.label.localeCompare(b.nav.label)), [catalog]);
  const widgets = useMemo(() => catalog.flatMap((ext) => (ext.admin.dashboardWidgets ?? []).map((widget) => ({ ext, widget }))), [catalog]);
  const actions = useMemo(() => catalog.flatMap((ext) => (ext.admin.actions ?? []).map((action) => ({ ext, action }))), [catalog]);
  const currentExt = selected ? catalog.find((e) => extensionKey(e) === selected.key) : undefined;

  const openPage = (ext: AdminExtension, pageId: string, actionId?: string) => setSelected({ key: extensionKey(ext), pageId, actionId });

  async function hostAction(item: ManagerItem, action: 'start'|'stop'|'restart') {
    const install = item.install ?? {}; const id = install.extensionId; if (!id) return;
    const params = new URLSearchParams({ scope: install.scope ?? 'global' }); if (install.scopeId) params.set('scopeId', install.scopeId);
    await api(backendUrl, `/api/v1/admin/extension-hosts/${encodeURIComponent(id)}/${action}?${params}`, token, { method: 'POST' });
    await refresh();
  }
  async function lifecycleAction(item: ManagerItem, action: 'enable'|'disable') {
    const install = item.install ?? {}; const id = install.extensionId; if (!id) return;
    await api(backendUrl, `/api/v1/admin/extension-installs/${encodeURIComponent(id)}/${action}`, token, { method: 'POST', body: JSON.stringify({ scope: install.scope ?? 'global', scopeId: install.scopeId ?? '' }) });
    await refresh();
  }

  if (mode === 'dashboard') return <section className="extensionWidgets">
    {actions.filter(({action}) => action.placement === 'dashboard').map(({ext,action}) => <button key={`${extensionKey(ext)}:${action.id}`} onClick={() => openPage(ext, action.pageId, action.id)}>{action.label}</button>)}
    {widgets.map(({ext,widget}) => <article className="extensionWidget" key={`${extensionKey(ext)}:${widget.id}`}><h3>{widget.title}</h3><AdminExtensionFrame backendUrl={backendUrl} token={token} extension={ext} pageId={widget.pageId} height={widget.height ?? 280} /></article>)}
  </section>;

  return <section className="adminExtensionsWorkspace">
    <div className="registryHeading"><div><h2>Администратор Расширения</h2><p className="muted">UI расширения работают только в песочница iframe. Скрипт расширение не загружается в основной React комплект; данные доступны только через типизированный разрешение-учитывающий RPC.</p></div><button onClick={refresh} disabled={loading}>{loading ? 'Обновление…' : 'Обновить'}</button></div>
    {localError && <p className="error">{localError}</p>}
    <div className="extensionToolbar">{actions.filter(({action}) => (action.placement ?? 'toolbar') === 'toolbar').map(({ext,action}) => <button key={`${extensionKey(ext)}:${action.id}`} onClick={() => openPage(ext, action.pageId, action.id)}>{action.label}</button>)}</div>
    <div className="extensionWorkspaceGrid">
      <nav className="extensionNav" aria-label="Навигация расширения">{nav.length === 0 && <span className="muted">Нет navigation contributions</span>}{nav.map(({ext,nav: n}) => <button key={`${extensionKey(ext)}:${n.id}`} className={selected?.key===extensionKey(ext)&&selected?.pageId===n.pageId?'active':''} onClick={() => openPage(ext,n.pageId)}>{n.label}<small>{ext.name}</small></button>)}</nav>
      <div className="extensionPageHost">{currentExt && selected ? <AdminExtensionFrame backendUrl={backendUrl} token={token} extension={currentExt} pageId={selected.pageId} actionId={selected.actionId} /> : <div className="extensionEmpty"><strong>Расширение страница</strong><p className="muted">Выберите вкладку из расширение navigation или действие.</p></div>}</div>
    </div>
    <h2>Расширение Диспетчер</h2>
    <div className="extensionManagerGrid">{(manager.items ?? []).map((item, index) => { const install=item.install??{}; const runtime=item.runtime??{}; const logs=item.logs??[]; const permissions=item.permissions??{}; return <article className="subcard" key={`${install.scope}:${install.scopeId??''}:${install.extensionId??index}`}>
      <div className="registryHeading"><div><strong>{install.extensionId ?? 'extension'} · {install.currentVersion ?? install.desiredVersion ?? '—'}</strong><p className="muted">{install.scope ?? 'global'} {install.scopeId ? `· ${install.scopeId}` : ''} · generation {install.generation ?? 0}</p></div><span className={`badge ${runtime.healthy ? 'ok' : 'warn'}`}>{runtime.state ?? install.currentState ?? 'unknown'}</span></div>
      <p className="muted">PID {runtime.pid ?? '—'} · restarts {runtime.restarts ?? 0} · RSS {runtime.memoryBytes ? `${Math.round(runtime.memoryBytes/1024/1024)} MiB` : '—'} · processes {runtime.processCount ?? '—'}</p>
      {runtime.lastError && <p className="error">{runtime.lastError}</p>}{install.lastError && <p className="error">{install.lastError}</p>}
      <p className="muted">Effective capabilities: {(permissions.effective ?? []).join(', ') || 'none'}{(permissions.missing ?? []).length ? ` · missing: ${(permissions.missing ?? []).join(', ')}` : ''}</p>
      <div className="buttonRow"><button onClick={() => hostAction(item,'start')}>Host Start</button><button onClick={() => hostAction(item,'stop')}>Host Stop</button><button onClick={() => hostAction(item,'restart')}>Host Restart</button><button onClick={() => lifecycleAction(item,'enable')}>Enable</button><button onClick={() => lifecycleAction(item,'disable')}>Disable</button></div>
      <details><summary>Последние логи ({logs.length})</summary><pre className="extensionLogs">{logs.map((l:any) => `${l.timestamp ?? ''} ${l.stream ?? ''} ${l.level ?? ''} ${l.message ?? ''}`).join('\n') || 'Нет журналов среды выполнения'}</pre></details>
    </article>; })}</div>
  </section>;
}
