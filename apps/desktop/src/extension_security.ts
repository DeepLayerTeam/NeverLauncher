/** Fail-closed checks for untrusted Desktop extension catalog / HTML / RPC. */
export const EXTENSION_PROTOCOL_0356 = "extensions.desktop-rpc.v1";
export const EXTENSION_API_0356 = "1.0";
const MAX_HTML = 2 * 1024 * 1024;
export const MAX_RPC_BYTES_0356 = 64 * 1024;

export type ExtensionIdentity0356 = {
  extensionId: string;
  version: string;
  generation: number;
  scope: string;
  scopeId?: string;
};
const id = (value: unknown): value is string =>
  typeof value === "string" && /^[a-z0-9][a-z0-9._-]{1,127}$/.test(value);
export function identity0356(item: ExtensionIdentity0356): string {
  return `${item.scope}:${item.scopeId ?? ""}:${item.extensionId}:${item.version}:${item.generation}`;
}
export function validExtension0356(
  item: unknown,
  projectId: string,
): item is ExtensionIdentity0356 & {
  bridgeAllowed: boolean;
  desktop: { pages: unknown[]; navigation?: unknown[]; actions?: unknown[] };
} {
  if (!item || typeof item !== "object") return false;
  const x = item as Record<string, unknown>;
  if (
    !id(x.extensionId) ||
    typeof x.version !== "string" ||
    x.version.length > 80 ||
    !Number.isSafeInteger(x.generation) ||
    Number(x.generation) < 0 ||
    (x.scope !== "global" && x.scope !== "project") ||
    typeof x.bridgeAllowed !== "boolean"
  )
    return false;
  if (x.scope === "project" && (!id(x.scopeId) || x.scopeId !== projectId))
    return false;
  if (x.scope === "global" && x.scopeId !== undefined && x.scopeId !== "")
    return false;
  const d = x.desktop as Record<string, unknown> | null;
  if (
    !d ||
    !Array.isArray(d.pages) ||
    d.pages.length > 64 ||
    !d.pages.every((p: unknown) => {
      if (!p || typeof p !== "object") return false;
      const v = p as Record<string, unknown>;
      return id(v.id) && typeof v.title === "string" && v.title.length <= 120;
    })
  )
    return false;
  for (const field of ["navigation", "actions"]) {
    const entries = d[field];
    if (entries === undefined) continue;
    if (
      !Array.isArray(entries) ||
      entries.length > 128 ||
      !entries.every((entry: unknown) => {
        if (!entry || typeof entry !== "object") return false;
        const v = entry as Record<string, unknown>;
        return (
          id(v.id) &&
          id(v.pageId) &&
          typeof v.label === "string" &&
          v.label.length <= 120
        );
      })
    )
      return false;
  }
  return true;
}
export function verifiedEntrypoint0356(
  data: unknown,
  item: ExtensionIdentity0356,
): string {
  if (!data || typeof data !== "object")
    throw new Error("Invalid extension entrypoint");
  const x = data as Record<string, unknown>;
  if (
    x.protocol !== EXTENSION_PROTOCOL_0356 ||
    x.extensionApiVersion !== EXTENSION_API_0356 ||
    x.extensionId !== item.extensionId ||
    x.version !== item.version ||
    x.generation !== item.generation ||
    typeof x.html !== "string" ||
    x.html.length > MAX_HTML
  )
    throw new Error("Stale or oversized extension entrypoint");
  return x.html;
}
export function validRPC0356(
  data: unknown,
): data is {
  protocol: string;
  type: "rpc.request";
  id: string;
  method: string;
  params?: unknown;
} {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  const x = data as Record<string, unknown>;
  if (
    x.protocol !== EXTENSION_PROTOCOL_0356 ||
    x.type !== "rpc.request" ||
    !id(x.id) ||
    x.id.length > 160 ||
    typeof x.method !== "string" ||
    !/^([a-zA-Z][a-zA-Z0-9]*)([.][a-zA-Z][a-zA-Z0-9]*)?$/.test(x.method) ||
    x.method.length > 64
  )
    return false;
  try {
    return JSON.stringify(x.params ?? {}).length <= MAX_RPC_BYTES_0356;
  } catch {
    return false;
  }
}
export function authorizedBridge0356(
  response: unknown,
  item: ExtensionIdentity0356,
  action: string,
): boolean {
  if (!response || typeof response !== "object") return false;
  const x = response as Record<string, unknown>;
  return (
    x.authorized === true &&
    x.extensionId === item.extensionId &&
    x.version === item.version &&
    x.generation === item.generation &&
    x.action === action
  );
}
