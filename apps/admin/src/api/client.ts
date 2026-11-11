/** Общий HTTP-контракт экранов Admin. Решения об авторизации принимаются на сервере. */
export interface ApiFailure { code?: number | string; message?: string; reasonCode?: string; blockers?: Array<{reasonCode:string;resource:string;message:string;action:string}> }
export type ApiEnvelope<T> = T | { data: T; error?: ApiFailure };
export type Collection<T> = { items: T[]; count?: number; total?: number; nextCursor?: string };

/** Локализованный HTTP-статус для журналов и сообщений интерфейса. */
export function httpStatusRu(response: Pick<Response, 'status'>): string {
  const explanations: Record<number, string> = {
    400: 'Некорректный запрос', 401: 'Требуется авторизация',
    403: 'Доступ запрещён', 404: 'Не найдено',
    408: 'Время ожидания запроса истекло', 409: 'Конфликт данных',
    410: 'Ресурс больше недоступен', 413: 'Слишком большой запрос',
    415: 'Неподдерживаемый формат данных', 422: 'Не удалось обработать запрос',
    423: 'Ресурс заблокирован', 429: 'Слишком много запросов',
    500: 'Внутренняя ошибка сервера', 501: 'Операция не поддерживается сервером',
    502: 'Ошибка шлюза', 503: 'Сервис временно недоступен',
    504: 'Время ответа сервера истекло',
  };
  return `HTTP ${response.status}: ${explanations[response.status] ?? 'Ошибка запроса к серверу'}`;
}

/** Русский текст сетевых ошибок браузера; исходные ошибки API и их коды не меняются. */
export function networkErrorRu(value: unknown): string {
  const message = value instanceof Error ? value.message : String(value ?? '');
  if (!message.trim()) return 'Причина не указана';
  if (/^(?:(?:TypeError|NetworkError):\s*)?(?:Failed to fetch|Network request failed|Load failed|fetch failed)$/i.test(message.trim()))
    return 'Не удалось выполнить сетевой запрос';
  if (/^NetworkError when attempting to fetch resource\.?$/i.test(message.trim()))
    return 'Сетевая ошибка при обращении к серверу';
  if (/^(?:AbortError:\s*)?(?:The operation was aborted|The user aborted a request|This operation was aborted)\.?$/i.test(message.trim()))
    return 'Операция прервана';
  if (/^(?:AbortError|TimeoutError):?$/i.test(message.trim())) return 'Время ожидания операции истекло';
  if (/^getaddrinfo ENOTFOUND\b|^connect (?:ETIMEDOUT|ECONNREFUSED)\b/i.test(message.trim()))
    return 'Не удалось подключиться к серверу (ошибка сети)';
  return message;
}

export class ApiError extends Error {
  readonly status: number; readonly reasonCode?: string; readonly blockers: NonNullable<ApiFailure['blockers']>;
  constructor(status: number, message: string, reasonCode?: string, blockers: NonNullable<ApiFailure['blockers']> = []) { super(message); this.name = 'ApiError'; this.status = status; this.reasonCode = reasonCode; this.blockers = blockers; }
}

/** Изменение могло достичь Backend, даже если ответ HTTP потерян. Никогда
 * не повторяйте его автоматически с новым ключом идемпотентности. */
export class IndeterminateApiError extends Error {
  readonly method: string;
  constructor(method: string, message: string) { super(message); this.name = 'IndeterminateApiError'; this.method = method; }
}

export async function requestJSON<T>(backendUrl: string, path: string, token?: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Некорректный путь API');
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
    const message = networkErrorRu(cause);
    if (mutation) throw new IndeterminateApiError(method,
      `Нет ответа сервера (${message}). Результат операции неизвестен: проверьте задание и журнал аудита. Повторять запрос можно только с прежним ключом идемпотентности.`);
    throw new ApiError(0, `Сервер недоступен (${message}). Проверьте соединение и обновите страницу.`, 'backend-unavailable');
  }
  let payload: unknown;
  try { payload = response.status === 204 ? null : await response.json(); }
  catch {
    if (response.ok && mutation) throw new IndeterminateApiError(method, 'Сервер вернул ответ не в формате JSON после изменения данных. Результат неизвестен: перед повтором проверьте журнал аудита и задание.');
    if (response.ok) throw new ApiError(response.status, 'Сервер вернул некорректный JSON. Повторите чтение.', 'invalid-backend-response');
    throw new ApiError(response.status, `HTTP ${response.status}: Сервер вернул ответ без структурированной ошибки`, 'invalid-backend-response');
  }
  if (!response.ok) {
    const failure = (payload && typeof payload === 'object' && 'error' in payload ? (payload as { error: ApiFailure }).error : undefined);
    throw new ApiError(response.status, failure?.message || httpStatusRu(response), failure?.reasonCode, Array.isArray(failure?.blockers) ? failure.blockers : []);
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
