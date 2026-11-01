/** Public NeverLauncher REST v1 client, separate from the extension iframe SDK. */
import { OPERATIONS, type OperationId } from './operations.generated.js';
export { OPERATIONS, type OperationId } from './operations.generated.js';
export const CONTRACT_VERSION = '1.0.0';
const MAX_BODY = 8 * 1024 * 1024;

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly requestId: string) { super(message); this.name = 'ApiError'; }
}
export function resolvePath(template: string, parameters: Record<string, string> = {}): string {
  if (!template.startsWith('/') || template.includes('?') || template.includes('#')) throw new Error('invalid route');
  const used = new Set<string>();
  const path = template.replace(/\{([^{}]+)\}/g, (_, name: string) => {
    const value = parameters[name]; used.add(name);
    if (!value || value === '.' || value === '..' || /[/\\]/.test(value)) throw new Error(`invalid path parameter: ${name}`);
    return encodeURIComponent(value);
  });
  for (const key of Object.keys(parameters)) if (!used.has(key)) throw new Error(`unexpected parameter: ${key}`);
  if (/[{}]/.test(path)) throw new Error('unresolved parameter');
  return path;
}
export type RequestOptions = {
  params?: Record<string, string>; query?: Record<string, string | number | boolean>;
  body?: unknown; idempotencyKey?: string; signal?: AbortSignal;
  // For multipart or binary API endpoints pass FormData/Blob/Uint8Array directly.
  rawBody?: BodyInit; contentType?: string;
};
export class NeverLauncherAPI {
  readonly baseURL: string;
  constructor(baseURL: string, private readonly token: string = '', private readonly transport: typeof fetch = fetch) {
    const u = new URL(baseURL);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) throw new Error('invalid API base URL');
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(host))) throw new Error('API requires HTTPS');
    this.baseURL = u.origin;
  }
  async call<T = unknown>(operationId: OperationId, options: RequestOptions = {}): Promise<T> {
    const op = OPERATIONS[operationId];
    return this.request<T>(op.method, resolvePath(op.path, options.params), options);
  }
  async request<T = unknown>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    if (!/^\/(?:api\/v1\/|health$|ready$|metrics$|api\/profiles\/minecraft|api\/user\/profile\/|authserver\/|sessionserver\/)/.test(path) || path.includes('..') || path.includes('?') || path.includes('#')) throw new Error('unsafe API route');
    if (options.body !== undefined && options.rawBody !== undefined) throw new Error('select one request body');
    const url = new URL(path, this.baseURL);
    Object.entries(options.query ?? {}).forEach(([k, v]) => url.searchParams.set(k, String(v)));
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (options.idempotencyKey) {
      if (/[\r\n]/.test(options.idempotencyKey)) throw new Error('invalid idempotency key');
      headers['Idempotency-Key'] = options.idempotencyKey;
    }
    let body: BodyInit | undefined;
    if (options.rawBody !== undefined) { body = options.rawBody; if (options.contentType) headers['Content-Type'] = options.contentType; }
    else if (options.body !== undefined) { body = JSON.stringify(options.body); headers['Content-Type'] = 'application/json'; }
    const response = await this.transport(url, { method, headers, body, signal: options.signal, redirect: 'manual' });
    const size = Number(response.headers.get('content-length') || 0);
    if (size > MAX_BODY) throw new Error('API response exceeds 8 MiB');
    // Stream with a real cap even when Content-Length is absent or untrusted.
    const reader = response.body?.getReader();
    const parts: Uint8Array[] = []; let total = 0;
    if (reader) {
      try {
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          total += value.byteLength; if (total > MAX_BODY) { await reader.cancel(); throw new Error('API response exceeds 8 MiB'); }
          parts.push(value);
        }
      } finally { reader.releaseLock(); }
    }
    const raw = new Uint8Array(total); let offset = 0;
    for (const part of parts) { raw.set(part, offset); offset += part.byteLength; }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    let parsed: unknown = undefined;
    if (text.trim()) { try { parsed = JSON.parse(text); } catch { if (response.ok) throw new Error('invalid JSON API response'); } }
    if (!response.ok) {
      const error = (parsed && typeof parsed === 'object') ? parsed as Record<string, unknown> : {};
      throw new ApiError(response.status, String(error.code ?? ''), String(error.message ?? error.error ?? response.statusText), response.headers.get('x-correlation-id') ?? '');
    }
    return parsed as T;
  }
  async checkCompatibility(): Promise<void> {
    // 0.45.11 did not emit the contract header; use its /ready product version as fallback.
    const response = await this.transport(new URL('/ready', this.baseURL), { redirect: 'manual' });
    if (!response.ok) throw new Error(`backend not ready: ${response.status}`);
    const version = response.headers.get('X-Launcher-API-Contract');
    if (version) { if (version !== CONTRACT_VERSION) throw new Error(`incompatible API contract: ${version}`); return; }
    const info = await response.json() as { version?: string };
    if (!['0.45.11', '0.45.12'].includes(info.version ?? '')) throw new Error(`unsupported legacy backend: ${info.version}`);
  }
}
