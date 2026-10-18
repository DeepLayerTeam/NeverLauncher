/** HTTP contract shared by Admin screens. Authorization decisions remain server-side. */
export interface ApiFailure { code?: number | string; message?: string; reasonCode?: string }
export type ApiEnvelope<T> = T | { data: T; error?: ApiFailure };
export type Collection<T> = { items: T[]; count?: number; total?: number; nextCursor?: string };

export class ApiError extends Error {
  readonly status: number; readonly reasonCode?: string;
  constructor(status: number, message: string, reasonCode?: string) { super(message); this.name = 'ApiError'; this.status = status; this.reasonCode = reasonCode; }
}

export async function requestJSON<T>(backendUrl: string, path: string, token?: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid API path');
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${backendUrl.replace(/\/$/, '')}${path}`, { ...init, headers, cache: 'no-store' });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const failure = (payload && typeof payload === 'object' && 'error' in payload ? (payload as { error: ApiFailure }).error : undefined);
    throw new ApiError(response.status, failure?.message || `${response.status} ${response.statusText}`, failure?.reasonCode);
  }
  if (payload && typeof payload === 'object' && 'data' in payload) return (payload as { data: T }).data;
  return payload as T;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function collection<T extends Record<string, unknown>>(input: unknown, key = 'items'): T[] {
  if (Array.isArray(input)) return input.filter(isRecord) as T[];
  if (isRecord(input) && Array.isArray(input[key])) return input[key].filter(isRecord) as T[];
  return [];
}
