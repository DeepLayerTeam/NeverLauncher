import React, { useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

const DESKTOP_EXTENSION_PROTOCOL = 'neverextensions.desktop-rpc.v1';
const EXTENSION_API_VERSION = '1.0';
const MAX_INFLIGHT = 16;

type DesktopPage = { id: string; title: string; description?: string };
type DesktopNavigation = { id: string; label: string; pageId: string; order?: number };
type DesktopAction = { id: string; label: string; pageId: string; placement?: 'toolbar' | 'page' | string };
type DesktopContributions = { pages?: DesktopPage[]; navigation?: DesktopNavigation[]; actions?: DesktopAction[] };
export type DesktopExtensionCatalogItem = {
  extensionId: string;
  name: string;
  version: string;
  scope: 'global' | 'project' | string;
  scopeId?: string;
  generation: number;
  bridgeAllowed: boolean;
  desktop: DesktopContributions;
};

type RPCRequest = { protocol: string; type: 'rpc.request'; id: string; method: string; params?: unknown };
type RPCResponse = { protocol: string; type: 'rpc.response'; id: string; result?: unknown; error?: string };
type EntrypointResponse = { data?: { protocol: string; extensionApiVersion: string; extensionId: string; version: string; generation: number; html: string } };

type Props = {
  backendUrl: string;
  token: string;
  projectId: string;
  gameDirectory: string;
  log: (message: string) => void;
};

function queryFor(item: DesktopExtensionCatalogItem): string {
  const q = new URLSearchParams();
  q.set('scope', item.scope || 'global');
  if (item.scopeId) q.set('scopeId', item.scopeId);
  return q.toString();
}

export function DesktopExtensions0209({ backendUrl, token, projectId, gameDirectory, log }: Props) {
  const [items, setItems] = useState<DesktopExtensionCatalogItem[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [pageId, setPageId] = useState<string>('');
  const [html, setHtml] = useState<string>('');
  const [error, setError] = useState<string>('');
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const inflight = useRef(0);

  const current = useMemo(() => items.find((item) => item.extensionId === selected), [items, selected]);
  const pages = current?.desktop.pages ?? [];
  const navigation = [...(current?.desktop.navigation ?? [])].sort((a, b) => (a.order ?? 0) - (b.order ?? 0) || a.id.localeCompare(b.id));
  const actions = (current?.desktop.actions ?? []).filter((action) => action.pageId === pageId);

  async function authorized(path: string, init?: RequestInit): Promise<Response> {
    const base = backendUrl.trim().replace(/\/$/, '');
    if (!base || !token) throw new Error('Desktop session is required for extension runtime');
    const headers = new Headers(init?.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    if (init?.body) headers.set('Content-Type', 'application/json');
    return fetch(`${base}${path}`, { ...init, headers });
  }

  async function refresh() {
    setError('');
    try {
      const response = await authorized('/api/v1/desktop/extensions/catalog');
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (payload?.data?.protocol !== DESKTOP_EXTENSION_PROTOCOL || payload?.data?.extensionApiVersion !== EXTENSION_API_VERSION) throw new Error('Desktop extension catalog protocol/API mismatch');
      const next = (payload?.data?.items ?? []) as DesktopExtensionCatalogItem[];
      setItems(next);
      if (!next.length) { setSelected(''); setPageId(''); setHtml(''); return; }
      const keep = next.find((item) => item.extensionId === selected) ?? next[0];
      setSelected(keep.extensionId);
      const firstPage = keep.desktop.pages?.find((p) => p.id === pageId) ?? keep.desktop.pages?.[0];
      setPageId(firstPage?.id ?? '');
    } catch (e) {
      const message = String(e);
      setError(message);
      log(`Desktop Extensions catalog: ${message}`);
    }
  }

  async function loadEntrypoint(item: DesktopExtensionCatalogItem) {
    setError('');
    try {
      const response = await authorized(`/api/v1/desktop/extensions/${encodeURIComponent(item.extensionId)}/ui?${queryFor(item)}`);
      const payload = await response.json() as EntrypointResponse & { error?: { message?: string } };
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (payload.data?.protocol !== DESKTOP_EXTENSION_PROTOCOL || payload.data.extensionApiVersion !== EXTENSION_API_VERSION || typeof payload.data.html !== 'string') throw new Error('Desktop extension protocol/API mismatch');
      setHtml(payload.data.html);
    } catch (e) {
      const message = String(e);
      setHtml('');
      setError(message);
      log(`Desktop extension ${item.extensionId}: ${message}`);
    }
  }

  useEffect(() => { if (token && backendUrl) void refresh(); else { setItems([]); setHtml(''); } }, [backendUrl, token]);
  useEffect(() => { if (current) void loadEntrypoint(current); }, [current?.extensionId, current?.generation, current?.scope, current?.scopeId]);

  useEffect(() => {
    const listener = async (event: MessageEvent) => {
      const frame = iframeRef.current?.contentWindow;
      if (!frame || event.source !== frame || !current) return;
      const message = event.data as RPCRequest;
      if (!message || message.protocol !== DESKTOP_EXTENSION_PROTOCOL || message.type !== 'rpc.request' || typeof message.id !== 'string' || typeof message.method !== 'string') return;
      if (message.id.length > 160 || message.method.length > 64 || inflight.current >= MAX_INFLIGHT) {
        frame.postMessage({ protocol: DESKTOP_EXTENSION_PROTOCOL, type: 'rpc.response', id: message.id || 'invalid', error: 'RPC limit exceeded' } satisfies RPCResponse, '*');
        return;
      }
      inflight.current += 1;
      let result: unknown;
      let rpcError = '';
      try {
        if (message.method === 'tauri.platform') {
          if (!current.bridgeAllowed) throw new Error('desktop:bridge is not granted');
          result = await invoke('desktop_extension_platform_info');
        } else if (message.method === 'tauri.openGameDirectory') {
          if (!current.bridgeAllowed) throw new Error('desktop:bridge is not granted');
          if (!gameDirectory.trim()) throw new Error('game directory is not configured');
          result = await invoke('open_game_directory', { root: gameDirectory });
        } else {
          const response = await authorized(`/api/v1/desktop/extensions/${encodeURIComponent(current.extensionId)}/rpc?${queryFor(current)}`, {
            method: 'POST',
            body: JSON.stringify({ protocol: DESKTOP_EXTENSION_PROTOCOL, id: message.id, method: message.method, params: message.params ?? {} }),
          });
          const payload = await response.json();
          if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
          const rpc = payload?.data;
          if (rpc?.protocol !== DESKTOP_EXTENSION_PROTOCOL || rpc?.id !== message.id) throw new Error('Desktop RPC response mismatch');
          if (rpc.error) throw new Error(rpc.error);
          result = rpc.result;
        }
      } catch (e) { rpcError = String(e); }
      finally { inflight.current -= 1; }
      frame.postMessage({ protocol: DESKTOP_EXTENSION_PROTOCOL, type: 'rpc.response', id: message.id, ...(rpcError ? { error: rpcError } : { result }) } satisfies RPCResponse, '*');
    };
    window.addEventListener('message', listener);
    return () => window.removeEventListener('message', listener);
  }, [current, backendUrl, token, gameDirectory]);

  function notifyContext() {
    const frame = iframeRef.current?.contentWindow;
    if (!frame || !current) return;
    frame.postMessage({ protocol: DESKTOP_EXTENSION_PROTOCOL, type: 'host.context', context: { extensionId: current.extensionId, version: current.version, extensionApiVersion: EXTENSION_API_VERSION, pageId, scope: current.scope, scopeId: current.scopeId ?? '', actionId: '', bridgeAllowed: current.bridgeAllowed } }, '*');
  }
  function triggerAction(action: DesktopAction) {
    setPageId(action.pageId);
    iframeRef.current?.contentWindow?.postMessage({ protocol: DESKTOP_EXTENSION_PROTOCOL, type: 'host.action', actionId: action.id, pageId: action.pageId }, '*');
  }

  return <section className="desktopExtensions0209">
    <div className="desktopExtensionsHeader">
      <div><h3>Desktop Extensions</h3><p>Standalone extension UI runs in an opaque-origin sandbox. Tauri access is available only through the permission-aware parent bridge.</p></div>
      <button onClick={() => void refresh()}>Обновить</button>
    </div>
    {error && <pre>{error}</pre>}
    {!items.length ? <p>Нет доступных enabled Desktop extensions.</p> : <div className="desktopExtensionsLayout">
      <aside className="desktopExtensionNav">
        {items.map((item) => <button key={`${item.scope}:${item.scopeId ?? ''}:${item.extensionId}`} className={selected === item.extensionId ? 'active' : ''} onClick={() => { setSelected(item.extensionId); setPageId(item.desktop.pages?.[0]?.id ?? ''); }}>{item.name}<small>{item.version} · {item.scope}{item.scopeId ? `/${item.scopeId}` : ''}</small></button>)}
        {current && navigation.map((entry) => <button key={entry.id} className={pageId === entry.pageId ? 'active sub' : 'sub'} onClick={() => setPageId(entry.pageId)}>{entry.label}</button>)}
      </aside>
      <div className="desktopExtensionSurface">
        <div className="desktopExtensionToolbar"><strong>{pages.find((p) => p.id === pageId)?.title ?? current?.name}</strong><span>{current?.bridgeAllowed ? 'Tauri bridge granted' : 'sandbox only'}</span>{actions.map((action) => <button key={action.id} onClick={() => triggerAction(action)}>{action.label}</button>)}</div>
        {html ? <iframe ref={iframeRef} title={`${current?.name ?? 'Extension'}:${pageId}`} sandbox="allow-scripts" srcDoc={html} onLoad={notifyContext} /> : <div className="desktopExtensionEmpty">Extension UI unavailable.</div>}
      </div>
    </div>}
  </section>;
}
