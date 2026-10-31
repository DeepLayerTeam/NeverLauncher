import React, { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  identity0356,
  validExtension0356,
  verifiedEntrypoint0356,
  validRPC0356,
  authorizedBridge0356,
} from "./extension_security_0356";

const DESKTOP_EXTENSION_PROTOCOL = "extensions.desktop-rpc.v1";
const EXTENSION_API_VERSION = "1.0";
const MAX_INFLIGHT = 16;

type DesktopPage = { id: string; title: string; description?: string };
type DesktopNavigation = {
  id: string;
  label: string;
  pageId: string;
  order?: number;
};
type DesktopAction = {
  id: string;
  label: string;
  pageId: string;
  placement?: "toolbar" | "page" | string;
};
type DesktopContributions = {
  pages?: DesktopPage[];
  navigation?: DesktopNavigation[];
  actions?: DesktopAction[];
};
export type DesktopExtensionCatalogItem = {
  extensionId: string;
  name: string;
  version: string;
  scope: "global" | "project" | string;
  scopeId?: string;
  generation: number;
  bridgeAllowed: boolean;
  desktop: DesktopContributions;
};

type RPCRequest = {
  protocol: string;
  type: "rpc.request";
  id: string;
  method: string;
  params?: unknown;
};
type RPCResponse = {
  protocol: string;
  type: "rpc.response";
  id: string;
  result?: unknown;
  error?: string;
};
type EntrypointResponse = {
  data?: {
    protocol: string;
    extensionApiVersion: string;
    extensionId: string;
    version: string;
    generation: number;
    html: string;
  };
};

type Props = {
  backendUrl: string;
  token: string;
  projectId: string;
  gameDirectory: string;
  log: (message: string) => void;
};

function queryFor(item: DesktopExtensionCatalogItem): string {
  const q = new URLSearchParams();
  q.set("scope", item.scope || "global");
  if (item.scopeId) q.set("scopeId", item.scopeId);
  return q.toString();
}

export function DesktopExtensions0209({
  backendUrl,
  token,
  projectId,
  gameDirectory,
  log,
}: Props) {
  const [items, setItems] = useState<DesktopExtensionCatalogItem[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [pageId, setPageId] = useState<string>("");
  const [html, setHtml] = useState<string>("");
  const [error, setError] = useState<string>("");
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const inflight = useRef(0);
  const pendingIds = useRef(new Set<string>());
  const loadedIdentity = useRef("");
  const requestGeneration = useRef(0);

  const current = useMemo(
    () => items.find((item) => identity0356(item) === selected),
    [items, selected],
  );
  const pages = current?.desktop.pages ?? [];
  const navigation = [...(current?.desktop.navigation ?? [])].sort(
    (a, b) => (a.order ?? 0) - (b.order ?? 0) || a.id.localeCompare(b.id),
  );
  const actions = (current?.desktop.actions ?? []).filter(
    (action) => action.pageId === pageId,
  );

  async function authorized(
    path: string,
    init?: RequestInit,
  ): Promise<Response> {
    const base = backendUrl.trim().replace(/\/$/, "");
    if (!base || !token)
      throw new Error("Desktop session is required for extension runtime");
    const headers = new Headers(init?.headers || {});
    headers.set("Authorization", `Bearer ${token}`);
    if (init?.body) headers.set("Content-Type", "application/json");
    return fetch(`${base}${path}`, { ...init, headers });
  }

  async function refresh() {
    setError("");
    try {
      const response = await authorized("/api/v1/desktop/extensions/catalog");
      const payload = await response.json();
      if (!response.ok)
        throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (
        payload?.data?.protocol !== DESKTOP_EXTENSION_PROTOCOL ||
        payload?.data?.extensionApiVersion !== EXTENSION_API_VERSION
      )
        throw new Error("Desktop extension catalog protocol/API mismatch");
      if (
        !Array.isArray(payload?.data?.items) ||
        payload.data.items.length > 128
      )
        throw new Error("Invalid Desktop extension catalog");
      const next = (payload.data.items as unknown[]).filter(
        (x): x is DesktopExtensionCatalogItem =>
          validExtension0356(x, projectId),
      );
      setItems(next);
      if (selected && !next.some((x) => identity0356(x) === selected)) {
        loadedIdentity.current = "";
        setHtml("");
      }
      if (!next.length) {
        setSelected("");
        setPageId("");
        setHtml("");
        return;
      }
      const keep =
        next.find((item) => identity0356(item) === selected) ?? next[0];
      setSelected(identity0356(keep));
      const firstPage =
        keep.desktop.pages?.find((p) => p.id === pageId) ??
        keep.desktop.pages?.[0];
      setPageId(firstPage?.id ?? "");
    } catch (e) {
      const message = String(e);
      setError(message);
      log(`Desktop Extensions catalog: ${message}`);
    }
  }

  async function loadEntrypoint(item: DesktopExtensionCatalogItem) {
    const generation = ++requestGeneration.current;
    loadedIdentity.current = "";
    setHtml("");
    pendingIds.current.clear();
    setError("");
    try {
      const response = await authorized(
        `/api/v1/desktop/extensions/${encodeURIComponent(item.extensionId)}/ui?${queryFor(item)}`,
      );
      const payload = (await response.json()) as EntrypointResponse & {
        error?: { message?: string };
      };
      if (!response.ok)
        throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      const next = verifiedEntrypoint0356(payload.data, item);
      if (generation !== requestGeneration.current) return;
      loadedIdentity.current = identity0356(item);
      setHtml(next);
    } catch (e) {
      if (generation !== requestGeneration.current) return;
      setHtml("");
      loadedIdentity.current = "";
      const message = String(e);
      setError(message);
      log(`Desktop extension ${item.extensionId}: ${message}`);
    }
  }

  useEffect(() => {
    ++requestGeneration.current;
    loadedIdentity.current = "";
    pendingIds.current.clear();
    setHtml("");
    if (token && backendUrl) void refresh();
    else setItems([]);
    return () => {
      ++requestGeneration.current;
      loadedIdentity.current = "";
      pendingIds.current.clear();
    };
  }, [backendUrl, token, projectId]);
  useEffect(() => {
    if (current) void loadEntrypoint(current);
    return () => {
      ++requestGeneration.current;
      loadedIdentity.current = "";
      pendingIds.current.clear();
    };
  }, [
    current?.extensionId,
    current?.version,
    current?.generation,
    current?.scope,
    current?.scopeId,
  ]);

  useEffect(() => {
    const listener = async (event: MessageEvent) => {
      const frame = iframeRef.current?.contentWindow;
      // sandbox="allow-scripts" (without allow-same-origin) guarantees an opaque
      // origin. Do not process messages from descendants or navigated HTTPS pages.
      if (
        !frame ||
        event.source !== frame ||
        event.origin !== "null" ||
        !current ||
        loadedIdentity.current !== identity0356(current)
      )
        return;
      const message = event.data;
      if (!validRPC0356(message)) return;
      const identity = identity0356(current);
      if (
        inflight.current >= MAX_INFLIGHT ||
        pendingIds.current.has(message.id)
      ) {
        frame.postMessage(
          {
            protocol: DESKTOP_EXTENSION_PROTOCOL,
            type: "rpc.response",
            id: message.id,
            error: "RPC concurrency or duplicate ID rejected",
          } satisfies RPCResponse,
          "*",
        );
        return;
      }
      inflight.current += 1;
      pendingIds.current.add(message.id);
      const respond = (result: unknown, rpcError: string) => {
        if (
          iframeRef.current?.contentWindow !== frame ||
          loadedIdentity.current !== identity
        )
          return;
        frame.postMessage(
          {
            protocol: DESKTOP_EXTENSION_PROTOCOL,
            type: "rpc.response",
            id: message.id,
            ...(rpcError ? { error: rpcError } : { result }),
          } satisfies RPCResponse,
          "*",
        );
      };
      let result: unknown;
      let rpcError = "";
      try {
        // Never trust a catalog's old bridgeAllowed flag as authorization.
        // The existing Backend RPC enforces the current install, verified
        // device, permissions, scope, version and generation for every action.
        if (
          message.method === "tauri.platform" ||
          message.method === "tauri.openGameDirectory"
        ) {
          if (!current.bridgeAllowed)
            throw new Error("desktop:bridge is not granted");
          const response = await authorized(
            `/api/v1/desktop/extensions/${encodeURIComponent(current.extensionId)}/rpc?${queryFor(current)}`,
            {
              method: "POST",
              body: JSON.stringify({
                protocol: DESKTOP_EXTENSION_PROTOCOL,
                id: message.id,
                method: "bridge.authorize",
                params: {
                  action: message.method,
                  version: current.version,
                  generation: current.generation,
                },
              }),
            },
          );
          const payload = await response.json();
          if (
            !response.ok ||
            payload?.data?.protocol !== DESKTOP_EXTENSION_PROTOCOL ||
            payload?.data?.id !== message.id ||
            payload?.data?.error ||
            !authorizedBridge0356(
              payload?.data?.result,
              current,
              message.method,
            )
          )
            throw new Error("Desktop bridge authorization denied or stale");
          if (loadedIdentity.current !== identity)
            throw new Error("Extension view changed");
          if (message.method === "tauri.platform")
            result = await invoke("desktop_extension_platform_info");
          else {
            if (!gameDirectory.trim())
              throw new Error("Game directory not configured");
            result = await invoke("open_game_directory", {
              root: gameDirectory,
            });
          }
        } else {
          const response = await authorized(
            `/api/v1/desktop/extensions/${encodeURIComponent(current.extensionId)}/rpc?${queryFor(current)}`,
            {
              method: "POST",
              body: JSON.stringify({
                protocol: DESKTOP_EXTENSION_PROTOCOL,
                id: message.id,
                method: message.method,
                params: message.params ?? {},
              }),
            },
          );
          const payload = await response.json();
          if (!response.ok)
            throw new Error(
              payload?.error?.message || `HTTP ${response.status}`,
            );
          const rpc = payload?.data;
          if (
            rpc?.protocol !== DESKTOP_EXTENSION_PROTOCOL ||
            rpc?.id !== message.id
          )
            throw new Error("Desktop RPC response mismatch");
          if (rpc.error) throw new Error(String(rpc.error));
          result = rpc.result;
        }
      } catch (e) {
        rpcError = String(e);
      } finally {
        inflight.current = Math.max(0, inflight.current - 1);
        pendingIds.current.delete(message.id);
      }
      respond(result, rpcError);
    };
    window.addEventListener("message", listener);
    return () => window.removeEventListener("message", listener);
  }, [current, backendUrl, token, gameDirectory]);

  function notifyContext() {
    const frame = iframeRef.current?.contentWindow;
    if (!frame || !current) return;
    frame.postMessage(
      {
        protocol: DESKTOP_EXTENSION_PROTOCOL,
        type: "host.context",
        context: {
          extensionId: current.extensionId,
          version: current.version,
          extensionApiVersion: EXTENSION_API_VERSION,
          pageId,
          scope: current.scope,
          scopeId: current.scopeId ?? "",
          actionId: "",
          bridgeAllowed: current.bridgeAllowed,
        },
      },
      "*",
    );
  }
  function triggerAction(action: DesktopAction) {
    setPageId(action.pageId);
    iframeRef.current?.contentWindow?.postMessage(
      {
        protocol: DESKTOP_EXTENSION_PROTOCOL,
        type: "host.action",
        actionId: action.id,
        pageId: action.pageId,
      },
      "*",
    );
  }

  return (
    <section className="desktopExtensions0209">
      <div className="desktopExtensionsHeader">
        <div>
          <h3>Desktop Extensions</h3>
          <p>
            Standalone extension UI runs in an opaque-origin sandbox. Tauri
            access is available only through the permission-aware parent bridge.
          </p>
        </div>
        <button onClick={() => void refresh()}>Обновить</button>
      </div>
      {error && <pre>{error}</pre>}
      {!items.length ? (
        <p>Нет доступных enabled Desktop extensions.</p>
      ) : (
        <div className="desktopExtensionsLayout">
          <aside className="desktopExtensionNav">
            {items.map((item) => (
              <button
                key={`${item.scope}:${item.scopeId ?? ""}:${item.extensionId}`}
                className={selected === identity0356(item) ? "active" : ""}
                onClick={() => {
                  setSelected(identity0356(item));
                  setPageId(item.desktop.pages?.[0]?.id ?? "");
                }}
              >
                {item.name}
                <small>
                  {item.version} · {item.scope}
                  {item.scopeId ? `/${item.scopeId}` : ""}
                </small>
              </button>
            ))}
            {current &&
              navigation.map((entry) => (
                <button
                  key={entry.id}
                  className={pageId === entry.pageId ? "active sub" : "sub"}
                  onClick={() => setPageId(entry.pageId)}
                >
                  {entry.label}
                </button>
              ))}
          </aside>
          <div className="desktopExtensionSurface">
            <div className="desktopExtensionToolbar">
              <strong>
                {pages.find((p) => p.id === pageId)?.title ?? current?.name}
              </strong>
              <span>
                {current?.bridgeAllowed
                  ? "Tauri bridge granted"
                  : "sandbox only"}
              </span>
              {actions.map((action) => (
                <button key={action.id} onClick={() => triggerAction(action)}>
                  {action.label}
                </button>
              ))}
            </div>
            {html &&
            current &&
            loadedIdentity.current === identity0356(current) ? (
              <iframe
                key={identity0356(current)}
                ref={iframeRef}
                title={`${current?.name ?? "Extension"}:${pageId}`}
                sandbox="allow-scripts"
                srcDoc={html}
                onLoad={notifyContext}
              />
            ) : (
              <div className="desktopExtensionEmpty">
                Extension UI unavailable.
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
