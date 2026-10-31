/** Operator actions use the existing authenticated 0.20.x extension API.
 * No result is classified as successful until the authoritative install list
 * reflects the transition. MFA / phishing-resistant freshness is server-side.
 */
export type ExtensionScope0425 = { scope: "global" | "project"; scopeId: string };
export type ExtensionInstall0425 = {
  extensionId: string; scope: string; scopeId?: string; currentState: string;
  currentVersion?: string; previousVersion?: string; generation: number;
};
export type ExtensionRegistryVersion0425 = {
  extensionId: string; version: string; publisherId: string;
  channels?: string[]; yankedAt?: string | null;
};
export type ExtensionQuarantine0425 = {
  id: string; extensionId?: string; version?: string; reason: string;
  active: boolean; packageIdentity: string;
};
export type ExtensionEmergency0425 = {
  extensionId: string; scope: string; scopeId?: string; reason: string;
};
export type ExtensionOperation0425 = "install" | "enable" | "disable" | "update" | "rollback" | "uninstall";

const extensionID0425 = /^[a-z0-9][a-z0-9._-]{1,127}$/;
const version0425 = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;

export function checkScope0425(scope: ExtensionScope0425): ExtensionScope0425 {
  if (scope.scope === "global" && scope.scopeId === "") return scope;
  if (scope.scope === "project" && extensionID0425.test(scope.scopeId)) return scope;
  throw new Error("Некорректная область расширения: global без ID или project с ID проекта");
}
export function checkExtensionID0425(id: string): string {
  const cleaned = id.trim().toLowerCase();
  if (!extensionID0425.test(cleaned)) throw new Error("Некорректный extension ID");
  return cleaned;
}
export function lifecyclePayload0425(
  action: ExtensionOperation0425, scope: ExtensionScope0425,
  version = "", channel = "",
): Record<string, string> {
  checkScope0425(scope);
  const payload: Record<string, string> = { scope: scope.scope, scopeId: scope.scopeId };
  if (action === "install" && !version0425.test(version))
    throw new Error("Установка требует конкретную опубликованную версию");
  if (version && !version0425.test(version)) throw new Error("Некорректная версия SemVer");
  if (version && channel) throw new Error("Укажите версию или канал, но не оба одновременно");
  if (version) payload.version = version;
  if (channel) {
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(channel)) throw new Error("Некорректный канал");
    payload.channel = channel;
  }
  return payload;
}

export class ExtensionManagement0425 {
  private readonly backend: string;
  private readonly token: string;
  constructor(backend: string, token: string) { this.backend = backend; this.token = token; }
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!/^https?:\/\//.test(this.backend) || !this.token) throw new Error("Нет Backend URL или административной сессии");
    const response = await fetch(`${this.backend.replace(/\/$/, "")}${path}`, {
      ...init, cache: "no-store", credentials: "omit",
      headers: { Authorization: `Bearer ${this.token}`, ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
    });
    const body: any = await response.json().catch(() => null);
    if (!response.ok) {
      const err = body?.error;
      const message = typeof err === "string" ? err : err?.message;
      throw new Error(message || `HTTP ${response.status} ${response.statusText}`);
    }
    if (body == null || !Object.prototype.hasOwnProperty.call(body, "data"))
      throw new Error("Backend вернул ответ без data; состояние не подтверждено");
    return body.data as T;
  }
  async installs(): Promise<ExtensionInstall0425[]> {
    const data = await this.request<{ items: ExtensionInstall0425[] }>("/api/v1/admin/extension-installs");
    if (!Array.isArray(data.items)) throw new Error("Неверный ответ inventory расширений");
    return data.items;
  }
  async registry(query: string): Promise<ExtensionRegistryVersion0425[]> {
    const data = await this.request<{ items: ExtensionRegistryVersion0425[] }>(
      `/api/v1/admin/extension-registry/extensions?q=${encodeURIComponent(query.trim().slice(0, 120))}`,
    );
    if (!Array.isArray(data.items)) throw new Error("Неверный ответ реестра расширений");
    return data.items.filter(x => x && typeof x.extensionId === "string" && typeof x.version === "string" && !x.yankedAt);
  }
  async quarantine(): Promise<ExtensionQuarantine0425[]> {
    const data = await this.request<{ items: ExtensionQuarantine0425[] }>("/api/v1/admin/extension-quarantine?active=true");
    if (!Array.isArray(data.items)) throw new Error("Неверный ответ карантина");
    return data.items;
  }
  async emergency(): Promise<ExtensionEmergency0425[]> {
    const data = await this.request<{ items: ExtensionEmergency0425[] }>("/api/v1/admin/extension-emergency-disables");
    if (!Array.isArray(data.items)) throw new Error("Неверный ответ аварийных блокировок");
    return data.items;
  }
  async lifecycle(action: ExtensionOperation0425, id: string, scope: ExtensionScope0425, version = "", channel = "") {
    const body = lifecyclePayload0425(action, scope, version, channel);
    return this.request<{ status: string; install: ExtensionInstall0425 }>(
      `/api/v1/admin/extension-installs/${encodeURIComponent(checkExtensionID0425(id))}/${action}`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }
  async emergencyDisable(id: string, scope: ExtensionScope0425, reason: string) {
    checkScope0425(scope);
    if (reason.trim().length < 5) throw new Error("Для аварийного запрета нужна причина не короче 5 символов");
    return this.request(`/api/v1/admin/extensions/${encodeURIComponent(checkExtensionID0425(id))}/emergency-disable`,
      { method: "POST", body: JSON.stringify({ ...scope, reason: reason.trim() }) });
  }
  async emergencyClear(id: string, scope: ExtensionScope0425) {
    checkScope0425(scope);
    const params = new URLSearchParams({ scope: scope.scope, scopeId: scope.scopeId });
    return this.request(`/api/v1/admin/extensions/${encodeURIComponent(checkExtensionID0425(id))}/emergency-disable?${params}`,
      { method: "DELETE" });
  }
  async releaseQuarantine(id: string) {
    if (!id || id.length > 256) throw new Error("Некорректный quarantine ID");
    return this.request(`/api/v1/admin/extension-quarantine/${encodeURIComponent(id)}/release`,
      { method: "POST", body: "{}" });
  }
}

export function matchingInstall0425(installs: ExtensionInstall0425[], id: string, scope: ExtensionScope0425) {
  return installs.find(x => x.extensionId === id && x.scope === scope.scope && (x.scopeId ?? "") === scope.scopeId);
}
export function verifyLifecycle0425(
  action: ExtensionOperation0425, id: string, scope: ExtensionScope0425,
  before: ExtensionInstall0425[], after: ExtensionInstall0425[], response: { install: ExtensionInstall0425 },
): string {
  const previous = matchingInstall0425(before, id, scope);
  const current = matchingInstall0425(after, id, scope);
  if (action === "uninstall") {
    if (!current || current.currentState === "absent") return "absent";
  } else if (current && current.generation === response.install?.generation && current.currentVersion === response.install?.currentVersion) {
    if (action === "enable" && current.currentState === "enabled") return current.currentState;
    if (action === "disable" && current.currentState === "disabled") return current.currentState;
    if ((action === "install" || action === "update" || action === "rollback") && current.currentState !== "absent" &&
      (!previous || current.generation > previous.generation)) return current.currentState;
  }
  throw new Error("Backend ответил на операцию, но состояние в inventory ещё не подтверждено. Проверьте аудит перед повтором.");
}
