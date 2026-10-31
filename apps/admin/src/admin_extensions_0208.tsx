import React, { useEffect, useMemo, useRef, useState } from "react";
import { auditHref, recoveryAdvice } from "./admin/lifecycle";
import {
  ExtensionManagement0425,
  checkScope0425,
  verifyLifecycle0425,
  type ExtensionScope0425,
  type ExtensionRegistryVersion0425,
  type ExtensionQuarantine0425,
  type ExtensionEmergency0425,
  type ExtensionOperation0425,
} from "./admin/extension_management_0425";

const ADMIN_PROTOCOL = "extensions.admin-rpc.v1";
const EXTENSION_API_VERSION = "1.0";

type Envelope<T> = { data?: T; error?: { message?: string } };
export type AdminPage = { id: string; title: string; description?: string };
export type AdminNavigation = {
  id: string;
  label: string;
  pageId: string;
  order?: number;
};
export type AdminWidget = {
  id: string;
  title: string;
  pageId: string;
  height?: number;
};
export type AdminAction = {
  id: string;
  label: string;
  pageId: string;
  placement?: "toolbar" | "dashboard";
};
export type AdminContributions = {
  pages?: AdminPage[];
  navigation?: AdminNavigation[];
  dashboardWidgets?: AdminWidget[];
  actions?: AdminAction[];
};
export type RuntimeStatus = {
  state?: string;
  healthy?: boolean;
  pid?: number;
  restarts?: number;
  lastError?: string;
  memoryBytes?: number;
  processCount?: number;
  lastHeartbeatAt?: string;
  executionTrust?: string;
  isolationStatus?: string;
  isolationReasonCodes?: string[];
  effectiveRestrictions?: string[];
  osSandbox?: string;
  networkSandbox?: string;
  filesystemSandbox?: string;
  resourceIsolation?: string;
  maxRequestsPerSecond?: number;
  maxOutputBytes?: number;
  hostRequestsRejected?: number;
  hostOutputBytes?: number;
  hostActiveRequests?: number;
};
export type AdminExtension = {
  extensionId: string;
  name: string;
  version: string;
  scope: string;
  scopeId?: string;
  generation: number;
  packageIdentity?: string;
  admin: AdminContributions;
  runtime?: RuntimeStatus;
  lastError?: string;
};
type Catalog = {
  protocol: string;
  extensionApiVersion: string;
  sandbox: string;
  items: AdminExtension[];
};
type ManagerItem = {
  install?: Record<string, any>;
  manifest?: Record<string, any>;
  permissions?: Record<string, any>;
  runtime?: RuntimeStatus;
  logs?: Array<Record<string, any>>;
};
type ManagerData = { items?: ManagerItem[]; count?: number };

type Props = {
  backendUrl: string;
  token: string;
  mode?: "workspace" | "dashboard";
  onError?: (message: string) => void;
};

async function api<T>(
  backendUrl: string,
  path: string,
  token: string,
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
    Authorization: `Bearer ${token}`,
  };
  if (init.body && !headers["Content-Type"])
    headers["Content-Type"] = "application/json";
  const response = await fetch(`${backendUrl.replace(/\/$/, "")}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "omit",
    headers,
  });
  const payload = (await response.json().catch(() => ({}))) as Envelope<T> | T;
  if (!response.ok)
    throw new Error(
      (typeof (payload as Envelope<T>).error === "string"
        ? (payload as any).error
        : (payload as Envelope<T>).error?.message) ??
        `${response.status} ${response.statusText}`,
    );
  return ((payload as Envelope<T>).data ?? payload) as T;
}

function scopeQuery(ext: AdminExtension) {
  const p = new URLSearchParams({ scope: ext.scope });
  if (ext.scopeId) p.set("scopeId", ext.scopeId);
  return p.toString();
}

function AdminExtensionFrame({
  backendUrl,
  token,
  extension,
  pageId,
  actionId,
  height = 560,
}: {
  backendUrl: string;
  token: string;
  extension: AdminExtension;
  pageId: string;
  actionId?: string;
  height?: number;
}) {
  const frame = useRef<HTMLIFrameElement>(null);
  const inflight = useRef(0);
  const pending = useRef(new Set<string>());
  const frameGeneration = useRef(0);
  const [html, setHtml] = useState("");
  const [error, setError] = useState("");
  const scope = scopeQuery(extension);

  useEffect(() => {
    let cancelled = false;
    setHtml("");
    setError("");
    pending.current.clear();
    ++frameGeneration.current;
    api<{ html: string; protocol: string; extensionApiVersion: string }>(
      backendUrl,
      `/api/v1/admin/extensions/${encodeURIComponent(extension.extensionId)}/ui?${scope}`,
      token,
    )
      .then((data) => {
        if (
          data.protocol !== ADMIN_PROTOCOL ||
          data.extensionApiVersion !== EXTENSION_API_VERSION
        )
          throw new Error("Admin extension protocol/API mismatch");
        if (!cancelled) setHtml(data.html);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
      ++frameGeneration.current;
    };
  }, [
    backendUrl,
    token,
    extension.extensionId,
    extension.version,
    extension.generation,
    scope,
  ]);

  useEffect(() => {
    const onMessage = async (event: MessageEvent) => {
      if (
        !frame.current ||
        event.source !== frame.current.contentWindow ||
        event.origin !== "null"
      )
        return;
      const message = event.data as any;
      if (
        !message ||
        message.protocol !== ADMIN_PROTOCOL ||
        message.type !== "rpc.request" ||
        typeof message.id !== "string" ||
        typeof message.method !== "string"
      )
        return;
      if (
        message.id.length > 160 ||
        message.method.length > 64 ||
        pending.current.has(message.id)
      )
        return;
      let size: number;
      try {
        size = JSON.stringify(message.params ?? {}).length;
      } catch {
        return;
      }
      if (size > 64 * 1024) return;
      const currentInflight = inflight.current ?? 0;
      if (currentInflight >= 32) {
        frame.current.contentWindow?.postMessage(
          {
            protocol: ADMIN_PROTOCOL,
            type: "rpc.response",
            id: message.id,
            error: "Admin RPC concurrency limit exceeded",
          },
          "*",
        );
        return;
      }
      inflight.current = currentInflight + 1;
      pending.current.add(message.id);
      const source = frame.current.contentWindow;
      const generation = frameGeneration.current;
      try {
        const result = await api<any>(
          backendUrl,
          `/api/v1/admin/extensions/${encodeURIComponent(extension.extensionId)}/rpc?${scope}`,
          token,
          {
            method: "POST",
            body: JSON.stringify({
              protocol: ADMIN_PROTOCOL,
              id: message.id,
              method: message.method,
              params: message.params ?? {},
            }),
          },
        );
        if (
          source !== frame.current?.contentWindow ||
          generation !== frameGeneration.current
        )
          return;
        source?.postMessage(
          {
            protocol: ADMIN_PROTOCOL,
            type: "rpc.response",
            id: message.id,
            result: result.result,
            error: result.error,
          },
          "*",
        );
      } catch (err) {
        if (
          source !== frame.current?.contentWindow ||
          generation !== frameGeneration.current
        )
          return;
        source?.postMessage(
          {
            protocol: ADMIN_PROTOCOL,
            type: "rpc.response",
            id: message.id,
            error: err instanceof Error ? err.message : String(err),
          },
          "*",
        );
      } finally {
        inflight.current = Math.max(0, (inflight.current ?? 1) - 1);
        pending.current.delete(message.id);
      }
    };
    window.addEventListener("message", onMessage);
    return () => {
      window.removeEventListener("message", onMessage);
      pending.current.clear();
    };
  }, [backendUrl, token, extension.extensionId, scope]);

  const sendContext = () => {
    frame.current?.contentWindow?.postMessage(
      {
        protocol: ADMIN_PROTOCOL,
        type: "host.context",
        context: {
          extensionId: extension.extensionId,
          version: extension.version,
          extensionApiVersion: EXTENSION_API_VERSION,
          scope: extension.scope,
          scopeId: extension.scopeId ?? "",
          pageId,
          actionId: actionId ?? "",
        },
      },
      "*",
    );
    if (actionId)
      frame.current?.contentWindow?.postMessage(
        { protocol: ADMIN_PROTOCOL, type: "host.action", actionId, pageId },
        "*",
      );
  };

  if (error)
    return <div className="extensionFrameError">Extension UI: {error}</div>;
  if (!html)
    return (
      <div className="extensionFrameLoading">
        Загрузка sandboxed extension UI…
      </div>
    );
  return (
    <iframe
      ref={frame}
      className="extensionFrame"
      title={`${extension.name}: ${pageId}`}
      sandbox="allow-scripts"
      referrerPolicy="no-referrer"
      srcDoc={html}
      onLoad={sendContext}
      style={{ height }}
    />
  );
}

function extensionKey(ext: AdminExtension) {
  return `${ext.scope}:${ext.scopeId ?? ""}:${ext.extensionId}`;
}

export function AdminExtensions({
  backendUrl,
  token,
  mode = "workspace",
  onError,
}: Props) {
  const [catalog, setCatalog] = useState<AdminExtension[]>([]);
  const [manager, setManager] = useState<ManagerData>({});
  const [selected, setSelected] = useState<{
    key: string;
    pageId: string;
    actionId?: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const refreshGeneration = useRef(0);
  const [localError, setLocalError] = useState("");
  const [operationBusy, setOperationBusy] = useState(false);
  const [registryQuery, setRegistryQuery] = useState("");
  const [registry, setRegistry] = useState<ExtensionRegistryVersion0425[]>([]);
  const [quarantine, setQuarantine] = useState<ExtensionQuarantine0425[]>([]);
  const [emergency, setEmergency] = useState<ExtensionEmergency0425[]>([]);
  const [targetScope, setTargetScope] = useState<"global" | "project">(
    "global",
  );
  const [targetScopeId, setTargetScopeId] = useState("");
  const [updateVersions, setUpdateVersions] = useState<Record<string, string>>(
    {},
  );
  const [updateChannel, setUpdateChannel] = useState<Record<string, string>>(
    {},
  );
  const management = useMemo(
    () => new ExtensionManagement0425(backendUrl, token),
    [backendUrl, token],
  );
  const [operationResult, setOperationResult] = useState<{
    target: string;
    action: string;
    output: unknown;
  } | null>(null);

  const refresh = async () => {
    const generation = ++refreshGeneration.current;
    if (!token) {
      setCatalog([]);
      setManager({});
      setQuarantine([]);
      setEmergency([]);
      setRegistry([]);
      return;
    }
    setLoading(true);
    setLocalError("");
    try {
      const data = await api<Catalog>(
        backendUrl,
        "/api/v1/admin/extensions/catalog",
        token,
      );
      if (
        data.protocol !== ADMIN_PROTOCOL ||
        data.extensionApiVersion !== EXTENSION_API_VERSION
      )
        throw new Error("Admin extension catalog protocol/API mismatch");
      if (generation !== refreshGeneration.current) return;
      setCatalog(data.items ?? []);
      if (mode === "workspace") {
        const [m, q, e] = await Promise.all([
          api<ManagerData>(
            backendUrl,
            "/api/v1/admin/extensions/manager",
            token,
          ),
          management.quarantine(),
          management.emergency(),
        ]);
        if (!Array.isArray(m.items))
          throw new Error("Invalid extension manager inventory");
        if (generation !== refreshGeneration.current) return;
        setManager(m);
        setQuarantine(q);
        setEmergency(e);
      }
    } catch (err) {
      if (generation !== refreshGeneration.current) return;
      const message = err instanceof Error ? err.message : String(err);
      setLocalError(message);
      if (mode === "workspace") {
        setManager({});
        setQuarantine([]);
        setEmergency([]);
      }
      onError?.(message);
    } finally {
      if (generation === refreshGeneration.current) setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    return () => {
      ++refreshGeneration.current;
    };
  }, [backendUrl, token, mode]);

  const nav = useMemo(
    () =>
      catalog
        .flatMap((ext) =>
          (ext.admin.navigation ?? []).map((n) => ({ ext, nav: n })),
        )
        .sort(
          (a, b) =>
            (a.nav.order ?? 0) - (b.nav.order ?? 0) ||
            a.nav.label.localeCompare(b.nav.label),
        ),
    [catalog],
  );
  const widgets = useMemo(
    () =>
      catalog.flatMap((ext) =>
        (ext.admin.dashboardWidgets ?? []).map((widget) => ({ ext, widget })),
      ),
    [catalog],
  );
  const actions = useMemo(
    () =>
      catalog.flatMap((ext) =>
        (ext.admin.actions ?? []).map((action) => ({ ext, action })),
      ),
    [catalog],
  );
  const currentExt = selected
    ? catalog.find((e) => extensionKey(e) === selected.key)
    : undefined;

  const openPage = (ext: AdminExtension, pageId: string, actionId?: string) =>
    setSelected({ key: extensionKey(ext), pageId, actionId });

  async function lifecycleOperation(
    item: ManagerItem,
    action: "start" | "stop" | "restart" | "enable" | "disable",
  ) {
    const install = item.install ?? {};
    const id = String(install.extensionId ?? "");
    if (!id || operationBusy) return;
    const scope: ExtensionScope0425 = {
      scope: install.scope === "project" ? "project" : "global",
      scopeId: String(install.scopeId ?? ""),
    };
    if (
      !window.confirm(
        `Подтвердить ${action}: ${id}\nScope: ${scope.scope}/${scope.scopeId || "global"}`,
      )
    )
      return;
    setOperationBusy(true);
    setLocalError("");
    setOperationResult(null);
    try {
      let output: unknown;
      if (action === "enable" || action === "disable") {
        const before = await management.installs();
        const result = await management.lifecycle(action, id, scope);
        const after = await management.installs();
        verifyLifecycle0425(action, id, scope, before, after, result);
        output = result;
      } else {
        const params = new URLSearchParams({
          scope: scope.scope,
          scopeId: scope.scopeId,
        });
        output = await api(
          backendUrl,
          `/api/v1/admin/extension-hosts/${encodeURIComponent(id)}/${action}?${params}`,
          token,
          { method: "POST" },
        );
        const current = await api<{ host: RuntimeStatus }>(
          backendUrl,
          `/api/v1/admin/extension-hosts/${encodeURIComponent(id)}?${params}`,
          token,
        );
        if (
          !current.host ||
          (action === "stop" && current.host.state !== "stopped") ||
          (action !== "stop" &&
            (current.host.state === "stopped" ||
              current.host.state === "failed"))
        )
          throw new Error(
            "Host не подтвердил новое состояние; проверьте журнал, прежде чем повторять команду",
          );
      }
      const inventory = await api<ManagerData>(
        backendUrl,
        "/api/v1/admin/extensions/manager",
        token,
      );
      if (!Array.isArray(inventory.items))
        throw new Error("Не удалось обновить состояние Manager");
      setManager(inventory);
      setOperationResult({ target: id, action, output });
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      setLocalError(`${reason}. ${recoveryAdvice(reason)}`);
    } finally {
      setOperationBusy(false);
    }
  }

  const selectedScope = (): ExtensionScope0425 =>
    checkScope0425({
      scope: targetScope,
      scopeId: targetScope === "global" ? "" : targetScopeId.trim(),
    });

  async function searchRegistry() {
    if (operationBusy) return;
    setOperationBusy(true);
    setLocalError("");
    try {
      setRegistry(await management.registry(registryQuery));
    } catch (e) {
      setRegistry([]);
      setLocalError(String(e));
    } finally {
      setOperationBusy(false);
    }
  }

  async function executeManagement(
    action:
      | ExtensionOperation0425
      | "emergency-disable"
      | "emergency-clear"
      | "quarantine-release",
    id: string,
    scope: ExtensionScope0425,
    version = "",
    channel = "",
  ) {
    if (operationBusy) return;
    let reason = "";
    try {
      checkScope0425(scope);
    } catch (e) {
      setLocalError(String(e));
      return;
    }
    if (action === "emergency-disable") {
      const input = window.prompt(
        `Причина аварийной блокировки ${id} (не менее 5 символов):`,
      );
      if (input === null) return;
      reason = input.trim();
      if (reason.length < 5) {
        setLocalError("Укажите причину не короче 5 символов");
        return;
      }
    }
    if (
      !window.confirm(
        `Подтвердить ${action}: ${id}${version ? `@${version}` : ""}\nScope: ${scope.scope}/${scope.scopeId || "global"}\n${action === "uninstall" ? "Удаление пакета может быть необратимым." : "Операция будет проверена через Backend."}`,
      )
    )
      return;
    setOperationBusy(true);
    setLocalError("");
    setOperationResult(null);
    try {
      const before = await management.installs();
      let output: unknown;
      if (action === "emergency-disable") {
        output = await management.emergencyDisable(id, scope, reason);
      } else if (action === "emergency-clear") {
        output = await management.emergencyClear(id, scope);
      } else if (action === "quarantine-release") {
        output = await management.releaseQuarantine(id);
      } else {
        const result = await management.lifecycle(
          action,
          id,
          scope,
          version,
          channel,
        );
        output = result;
        const after = await management.installs();
        verifyLifecycle0425(action, id, scope, before, after, result);
      }
      // The inventory and safety lists must be refreshed, infer success
      // from a 200/201 response or optimistically alter the UI.
      const [nextManager, nextQuarantine, nextEmergency] = await Promise.all([
        api<ManagerData>(backendUrl, "/api/v1/admin/extensions/manager", token),
        management.quarantine(),
        management.emergency(),
      ]);
      if (!Array.isArray(nextManager.items))
        throw new Error("Manager inventory unavailable after action");
      setManager(nextManager);
      setQuarantine(nextQuarantine);
      setEmergency(nextEmergency);
      if (
        action === "emergency-disable" &&
        !nextEmergency.some(
          (x) =>
            x.extensionId === id &&
            x.scope === scope.scope &&
            (x.scopeId ?? "") === scope.scopeId,
        )
      )
        throw new Error("Аварийная блокировка не подтверждена на Backend");
      if (
        action === "emergency-clear" &&
        nextEmergency.some(
          (x) =>
            x.extensionId === id &&
            x.scope === scope.scope &&
            (x.scopeId ?? "") === scope.scopeId,
        )
      )
        throw new Error("Снятие блокировки не подтверждено на Backend");
      if (
        action === "quarantine-release" &&
        nextQuarantine.some((x) => x.id === id && x.active)
      )
        throw new Error("Карантин всё ещё активен");
      setOperationResult({ target: id, action, output });
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      setLocalError(`${reason}. ${recoveryAdvice(reason)}`);
    } finally {
      setOperationBusy(false);
    }
  }

  if (mode === "dashboard")
    return (
      <section className="extensionWidgets">
        {actions
          .filter(({ action }) => action.placement === "dashboard")
          .map(({ ext, action }) => (
            <button
              key={`${extensionKey(ext)}:${action.id}`}
              onClick={() => openPage(ext, action.pageId, action.id)}
            >
              {action.label}
            </button>
          ))}
        {widgets.map(({ ext, widget }) => (
          <article
            className="extensionWidget"
            key={`${extensionKey(ext)}:${widget.id}`}
          >
            <h3>{widget.title}</h3>
            <AdminExtensionFrame
              backendUrl={backendUrl}
              token={token}
              extension={ext}
              pageId={widget.pageId}
              height={widget.height ?? 280}
            />
          </article>
        ))}
      </section>
    );

  return (
    <section className="adminExtensionsWorkspace">
      <div className="registryHeading">
        <div>
          <h2>Admin Extensions</h2>
          <p className="muted">
            UI extensions работают только в sandboxed iframe. Скрипт extension
            не загружается в основной React bundle; данные доступны только через
            typed permission-aware RPC.
          </p>
        </div>
        <button onClick={refresh} disabled={loading}>
          {loading ? "Обновление…" : "Обновить"}
        </button>
      </div>
      {localError && <p className="error">{localError}</p>}
      {operationResult && (
        <article className="subcard" role="status">
          <strong>
            {operationResult.action}: {operationResult.target}
          </strong>
          <p>
            Backend вернул ответ. Актуальное состояние показано в списке
            установок после обновления.
          </p>
          <details>
            <summary>Результат</summary>
            <pre>{JSON.stringify(operationResult.output, null, 2)}</pre>
          </details>
          <a href={auditHref(operationResult.target)}>Открыть аудит</a>
        </article>
      )}
      <div className="extensionToolbar">
        {actions
          .filter(({ action }) => (action.placement ?? "toolbar") === "toolbar")
          .map(({ ext, action }) => (
            <button
              key={`${extensionKey(ext)}:${action.id}`}
              onClick={() => openPage(ext, action.pageId, action.id)}
            >
              {action.label}
            </button>
          ))}
      </div>
      <div className="extensionWorkspaceGrid">
        <nav className="extensionNav" aria-label="Extension navigation">
          {nav.length === 0 && (
            <span className="muted">Нет navigation contributions</span>
          )}
          {nav.map(({ ext, nav: n }) => (
            <button
              key={`${extensionKey(ext)}:${n.id}`}
              className={
                selected?.key === extensionKey(ext) &&
                selected?.pageId === n.pageId
                  ? "active"
                  : ""
              }
              onClick={() => openPage(ext, n.pageId)}
            >
              {n.label}
              <small>{ext.name}</small>
            </button>
          ))}
        </nav>
        <div className="extensionPageHost">
          {currentExt && selected ? (
            <AdminExtensionFrame
              backendUrl={backendUrl}
              token={token}
              extension={currentExt}
              pageId={selected.pageId}
              actionId={selected.actionId}
            />
          ) : (
            <div className="extensionEmpty">
              <strong>Extension pages</strong>
              <p className="muted">
                Выберите вкладку из extension navigation или action.
              </p>
            </div>
          )}
        </div>
      </div>
      <h2>Реестр и установка расширений</h2>
      <p className="muted">
        Устанавливаются только опубликованные подписанные версии из Backend
        Registry. Для операций обновления, отката и удаления Backend требует
        свежую MFA-сессию.
      </p>
      <div className="buttonRow">
        <input
          aria-label="Поиск расширений"
          value={registryQuery}
          onChange={(e) => setRegistryQuery(e.target.value)}
          placeholder="ID или название"
        />
        <button
          disabled={operationBusy || loading}
          onClick={() => void searchRegistry()}
        >
          Найти в реестре
        </button>
        <select
          aria-label="Область установки"
          value={targetScope}
          onChange={(e) =>
            setTargetScope(e.target.value as "global" | "project")
          }
        >
          <option value="global">Global</option>
          <option value="project">Project</option>
        </select>
        {targetScope === "project" && (
          <input
            aria-label="ID проекта"
            value={targetScopeId}
            onChange={(e) => setTargetScopeId(e.target.value)}
            placeholder="project ID"
          />
        )}
      </div>
      <div className="extensionManagerGrid">
        {registry.map((entry) => (
          <article
            className="subcard"
            key={`${entry.extensionId}:${entry.version}`}
          >
            <strong>
              {entry.extensionId} · {entry.version}
            </strong>
            <p className="muted">
              Издатель: {entry.publisherId} · Каналы:{" "}
              {(entry.channels ?? []).join(", ") || "—"}
            </p>
            <button
              disabled={operationBusy || loading}
              onClick={() => {
                try {
                  void executeManagement(
                    "install",
                    entry.extensionId,
                    selectedScope(),
                    entry.version,
                  );
                } catch (e) {
                  setLocalError(String(e));
                }
              }}
            >
              Установить версию
            </button>
          </article>
        ))}
      </div>
      <h2>Карантин и аварийные блокировки</h2>
      <div className="extensionManagerGrid">
        {quarantine.map((entry) => (
          <article className="subcard" key={entry.id}>
            <strong>
              Карантин: {entry.extensionId || entry.packageIdentity}
            </strong>
            <p className="error">{entry.reason}</p>
            <p className="muted">
              {entry.version || "—"} · {entry.id}
            </p>
            <button
              disabled={operationBusy}
              onClick={() =>
                void executeManagement("quarantine-release", entry.id, {
                  scope: "global",
                  scopeId: "",
                })
              }
            >
              Освободить из карантина (MFA)
            </button>
          </article>
        ))}
        {emergency.map((entry) => (
          <article
            className="subcard"
            key={`${entry.scope}:${entry.scopeId ?? ""}:${entry.extensionId}`}
          >
            <strong>Запрещено: {entry.extensionId}</strong>
            <p className="error">{entry.reason}</p>
            <p className="muted">
              {entry.scope}/{entry.scopeId || "global"}
            </p>
            <button
              disabled={operationBusy}
              onClick={() =>
                void executeManagement("emergency-clear", entry.extensionId, {
                  scope: entry.scope === "project" ? "project" : "global",
                  scopeId: entry.scopeId ?? "",
                })
              }
            >
              Снять блокировку
            </button>
          </article>
        ))}
      </div>
      <h2>Extension Manager</h2>
      <div className="extensionManagerGrid">
        {(manager.items ?? []).map((item, index) => {
          const install = item.install ?? {};
          const runtime = item.runtime ?? {};
          const logs = item.logs ?? [];
          const permissions = item.permissions ?? {};
          return (
            <article
              className="subcard"
              key={`${install.scope}:${install.scopeId ?? ""}:${install.extensionId ?? index}`}
            >
              <div className="registryHeading">
                <div>
                  <strong>
                    {install.extensionId ?? "extension"} ·{" "}
                    {install.currentVersion ?? install.desiredVersion ?? "—"}
                  </strong>
                  <p className="muted">
                    {install.scope ?? "global"}{" "}
                    {install.scopeId ? `· ${install.scopeId}` : ""} · generation{" "}
                    {install.generation ?? 0}
                  </p>
                </div>
                <span className={`badge ${runtime.healthy ? "ok" : "warn"}`}>
                  {runtime.state ?? install.currentState ?? "unknown"}
                </span>
              </div>
              <p className="muted">
                PID {runtime.pid ?? "—"} · restarts {runtime.restarts ?? 0} ·
                RSS{" "}
                {runtime.memoryBytes
                  ? `${Math.round(runtime.memoryBytes / 1024 / 1024)} MiB`
                  : "—"}{" "}
                · processes {runtime.processCount ?? "—"}
              </p>
              <section aria-label="OS sandbox security state">
                <p>
                  <strong>
                    Исполнение:{" "}
                    {runtime.isolationStatus === "isolated" &&
                    runtime.executionTrust === "os-isolated"
                      ? "OS-isolated"
                      : runtime.executionTrust === "legacy-unisolated"
                        ? "Без подтверждённой OS-изоляции"
                        : "Не подтверждено"}
                  </strong>{" "}
                  · {runtime.state ?? "not running"}
                </p>
                <p className="muted">
                  ОС: {runtime.osSandbox ?? "none"} · ресурсы:{" "}
                  {runtime.resourceIsolation ?? "not verified"} · сеть:{" "}
                  {runtime.networkSandbox ?? "not verified"} · файлы:{" "}
                  {runtime.filesystemSandbox ?? "not verified"}
                </p>
                {!!runtime.isolationReasonCodes?.length && (
                  <p className="error">
                    Причины отказа: {runtime.isolationReasonCodes.join(", ")}
                  </p>
                )}
                {runtime.isolationStatus === "isolated" && (
                  <p className="muted">
                    IPC ≤ {runtime.maxRequestsPerSecond ?? "—"} запросов/с ·
                    вывод {runtime.hostOutputBytes ?? 0} /{" "}
                    {runtime.maxOutputBytes ?? "—"} байт · отклонено{" "}
                    {runtime.hostRequestsRejected ?? 0} · выполняется{" "}
                    {runtime.hostActiveRequests ?? 0}
                  </p>
                )}
                {!!runtime.effectiveRestrictions?.length && (
                  <details>
                    <summary>Фактически применённые ограничения</summary>
                    <ul>
                      {runtime.effectiveRestrictions.map((value) => (
                        <li key={value}>{value}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </section>
              {runtime.lastError && (
                <p className="error">{runtime.lastError}</p>
              )}
              {install.lastError && (
                <p className="error">{install.lastError}</p>
              )}
              <p>
                <a href={auditHref(String(install.extensionId ?? ""))}>
                  Аудит расширения
                </a>
              </p>
              <p className="muted">
                Подписанный режим:{" "}
                {String(
                  item.manifest?.sandbox?.mode ?? "legacy / trusted-unconfined",
                )}{" "}
                · pid ≤ {item.manifest?.sandbox?.maxProcesses ?? "не задан"} ·
                память ≤ {item.manifest?.sandbox?.maxMemoryBytes ?? "не задана"}{" "}
                байт · CPU ≤{" "}
                {item.manifest?.sandbox?.maxCpuPercent ?? "не задан"}% · срок ≤{" "}
                {item.manifest?.sandbox?.timeoutSeconds ?? "не задан"} с. Эти
                требования не подтверждают фактическую изоляцию.
              </p>
              <p className="muted">
                Effective capabilities:{" "}
                {(permissions.effective ?? []).join(", ") || "none"}
                {(permissions.missing ?? []).length
                  ? ` · missing: ${(permissions.missing ?? []).join(", ")}`
                  : ""}
              </p>
              <div className="buttonRow">
                <button
                  disabled={operationBusy}
                  onClick={() => void lifecycleOperation(item, "start")}
                >
                  Host Start
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() => void lifecycleOperation(item, "stop")}
                >
                  Host Stop
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() => void lifecycleOperation(item, "restart")}
                >
                  Host Restart
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() => void lifecycleOperation(item, "enable")}
                >
                  Enable
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() => void lifecycleOperation(item, "disable")}
                >
                  Disable
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() =>
                    void executeManagement(
                      "update",
                      String(install.extensionId),
                      {
                        scope:
                          install.scope === "project" ? "project" : "global",
                        scopeId: String(install.scopeId ?? ""),
                      },
                      updateVersions[String(install.extensionId)] ?? "",
                      updateVersions[String(install.extensionId)]
                        ? ""
                        : (updateChannel[String(install.extensionId)] ??
                            "stable"),
                    )
                  }
                >
                  Update
                </button>
                <button
                  disabled={operationBusy || !install.previousVersion}
                  onClick={() =>
                    void executeManagement(
                      "rollback",
                      String(install.extensionId),
                      {
                        scope:
                          install.scope === "project" ? "project" : "global",
                        scopeId: String(install.scopeId ?? ""),
                      },
                    )
                  }
                >
                  Rollback
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() =>
                    void executeManagement(
                      "uninstall",
                      String(install.extensionId),
                      {
                        scope:
                          install.scope === "project" ? "project" : "global",
                        scopeId: String(install.scopeId ?? ""),
                      },
                    )
                  }
                >
                  Uninstall (MFA)
                </button>
                <button
                  disabled={operationBusy}
                  onClick={() =>
                    void executeManagement(
                      "emergency-disable",
                      String(install.extensionId),
                      {
                        scope:
                          install.scope === "project" ? "project" : "global",
                        scopeId: String(install.scopeId ?? ""),
                      },
                    )
                  }
                >
                  Emergency disable
                </button>
              </div>
              <div className="buttonRow">
                <label>
                  Версия обновления{" "}
                  <input
                    aria-label={`Версия обновления ${install.extensionId}`}
                    placeholder="1.2.3 (или оставьте пустым)"
                    value={updateVersions[String(install.extensionId)] ?? ""}
                    onChange={(e) =>
                      setUpdateVersions((prev) => ({
                        ...prev,
                        [String(install.extensionId)]: e.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  Канал{" "}
                  <input
                    aria-label={`Канал обновления ${install.extensionId}`}
                    value={
                      updateChannel[String(install.extensionId)] ?? "stable"
                    }
                    onChange={(e) =>
                      setUpdateChannel((prev) => ({
                        ...prev,
                        [String(install.extensionId)]: e.target.value,
                      }))
                    }
                  />
                </label>
              </div>
              <details>
                <summary>Последние логи ({logs.length})</summary>
                <pre className="extensionLogs">
                  {logs
                    .map(
                      (l: any) =>
                        `${l.timestamp ?? ""} ${l.stream ?? ""} ${l.level ?? ""} ${l.message ?? ""}`,
                    )
                    .join("\n") || "Нет runtime logs"}
                </pre>
              </details>
            </article>
          );
        })}
      </div>
    </section>
  );
}
