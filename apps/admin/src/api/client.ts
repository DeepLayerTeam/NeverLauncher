/** HTTP contract shared by Admin screens. Authorization decisions remain server-side. */
export interface ApiFailure { code?: number | string; message?: string; reasonCode?: string; blockers?: Array<{reasonCode:string;resource:string;message:string;action:string}> }
export type ApiEnvelope<T> = T | { data: T; error?: ApiFailure };
export type Collection<T> = { items: T[]; count?: number; total?: number; nextCursor?: string };

export class ApiError extends Error {
  readonly status: number; readonly reasonCode?: string; readonly blockers: NonNullable<ApiFailure['blockers']>;
  constructor(status: number, message: string, reasonCode?: string, blockers: NonNullable<ApiFailure['blockers']> = []) { super(message); this.name = 'ApiError'; this.status = status; this.reasonCode = reasonCode; this.blockers = blockers; }
}

/** A mutation may have reached Backend even if its HTTP response was lost.
 * Never automatically replay it using a fresh idempotency key. */
export class IndeterminateApiError extends Error {
  readonly method: string;
  constructor(method: string, message: string) { super(message); this.name = 'IndeterminateApiError'; this.method = method; }
}

export async function requestJSON<T>(backendUrl: string, path: string, token?: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid API path');
  const method = (init.method ?? 'GET').toUpperCase();
  const mutation = !['GET','HEAD','OPTIONS'].includes(method);
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(`${backendUrl.replace(/\/$/, '')}${path}`, { ...init, headers, cache: 'no-store' });
  } catch (cause) {
    if (init.signal?.aborted) throw cause;
    const message = cause instanceof Error ? cause.message : 'Сеть недоступна';
    if (mutation) throw new IndeterminateApiError(method,
      `Нет ответа Backend (${message}). Результат операции неизвестен: проверьте job/аудит или повторите запрос только с исходным idempotency key.`);
    throw new ApiError(0, `Backend недоступен (${message}). Проверьте соединение и обновите страницу.`, 'backend-unavailable');
  }
  let payload: unknown;
  try { payload = response.status === 204 ? null : await response.json(); }
  catch {
    if (response.ok && mutation) throw new IndeterminateApiError(method, 'Backend вернул не-JSON ответ после изменения. Результат неизвестен: проверьте аудит/job перед повтором.');
    if (response.ok) throw new ApiError(response.status, 'Backend вернул некорректный JSON. Повторите чтение.', 'invalid-backend-response');
    throw new ApiError(response.status, `HTTP ${response.status}: Backend вернул ответ без структурированной ошибки`, 'invalid-backend-response');
  }
  if (!response.ok) {
    const failure = (payload && typeof payload === 'object' && 'error' in payload ? (payload as { error: ApiFailure }).error : undefined);
    throw new ApiError(response.status, failure?.message || `${response.status} ${response.statusText}`, failure?.reasonCode, Array.isArray(failure?.blockers) ? failure.blockers : []);
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
