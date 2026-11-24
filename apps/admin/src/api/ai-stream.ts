/** HTTP/SSE wire protocol shared with the Desktop AI gateway. */
export const MAX_PROMPT_BYTES = 16_384;
export const MAX_QUESTION_BYTES = 12_288;
export const MAX_ANSWER_BYTES = 131_072;
const encoder = new TextEncoder();
export const byteLength = (text: string) => encoder.encode(text).length;
export type Receipt = {requestId: string; inputTokens: number; outputTokens: number; chargedMicroUsd: number};
export type ChatErrorCode = 'invalid' | 'unauthorized' | 'forbidden' | 'limit' | 'unavailable' | 'network' | 'protocol' | 'interrupted' | 'provider' | 'accounting' | 'revoked' | 'cancelled' | 'storage' | 'too_large';
export class ChatError extends Error { readonly code: ChatErrorCode; constructor(code: ChatErrorCode) {super(code); this.code=code;} }
const object = (v: unknown): Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
const validInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const shortText = (v: unknown, max: number): v is string => typeof v === 'string' && byteLength(v) <= max;
const validId = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
export function gatewayBase(raw: string): string {
  let url: URL;
  try {url = new URL(raw.trim());} catch {throw new ChatError('invalid');}
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new ChatError('invalid');
  return url.href.replace(/\/+$/, '');
}
function receipt(v: unknown): Receipt | undefined {
  const x = object(v);
  // Go omitempty omits legitimate zero counters in a terminal event.
  const inputTokens = x.inputTokens ?? 0, outputTokens = x.outputTokens ?? 0, chargedMicroUsd = x.chargedMicroUsd ?? 0;
  if (!validId(x.requestId) || !validInt(inputTokens) || !validInt(outputTokens) || !validInt(chargedMicroUsd)) return undefined;
  return {requestId: x.requestId, inputTokens, outputTokens, chargedMicroUsd};
}
function statusError(status: number): ChatError {return new ChatError(status === 401 ? 'unauthorized' : status === 403 ? 'forbidden' : status === 429 ? 'limit' : status === 400 ? 'invalid' : 'unavailable');}
function requestOptions(token: string, signal: AbortSignal): RequestInit {
  if (!token) throw new ChatError('unauthorized');
  return {headers: {Authorization: `Bearer ${token}`}, signal, credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer'};
}
/** SSE parser supports arbitrary byte/UTF-8 boundaries, CRLF, multiline data and comments. */
export async function readChatStream(body: ReadableStream<Uint8Array>, onDelta: (delta: string) => void): Promise<Receipt> {
  const reader = body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
  let buffer = '', event = '', data: string[] = [], eventBytes = 0, outputBytes = 0, streamBytes = 0, requestId = '';
  function line(s: string): Receipt | undefined {
    if (s.endsWith('\r')) s = s.slice(0, -1);
    if (s === '') {
      const name = event, payload = data.join('\n'); event = ''; data = []; eventBytes = 0;
      if (!payload) {if (name) throw new ChatError('protocol'); return;}
      let x: Record<string, unknown>;
      try {x = object(JSON.parse(payload));} catch {throw new ChatError('protocol');}
      if (name === 'start') {
        if (requestId || !validId(x.requestId)) throw new ChatError('protocol');
        requestId = x.requestId;
      } else if (name === 'delta') {
        if (!requestId || typeof x.delta !== 'string') throw new ChatError('protocol');
        outputBytes += byteLength(x.delta);
        if (outputBytes > MAX_ANSWER_BYTES) throw new ChatError('too_large');
        onDelta(x.delta);
      } else if (name === 'done') {
        const result = receipt(x);
        if (!requestId || x.state !== 'completed' || !result || result.requestId !== requestId) throw new ChatError('protocol');
        return result;
      } else if (name === 'error') {
        if (!requestId || (x.requestId !== undefined && x.requestId !== requestId)) throw new ChatError('protocol');
        throw new ChatError(x.code === 'access_revoked' ? 'revoked' : x.code === 'accounting_unavailable' ? 'accounting' : x.code === 'stream_cancelled' ? 'cancelled' : 'provider');
      } else throw new ChatError('protocol');
      return;
    }
    if (s.startsWith(':')) return;
    eventBytes += byteLength(s);
    if (eventBytes > 1024 * 1024) throw new ChatError('too_large');
    const colon = s.indexOf(':'), name = colon < 0 ? s : s.slice(0, colon), value = colon < 0 ? '' : s.slice(colon + 1).replace(/^ /, '');
    if (name === 'event') event = value;
    if (name === 'data') data.push(value);
  }
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {decoder.decode(); throw new ChatError('interrupted');}
      streamBytes += chunk.value.byteLength;
      if (streamBytes > 8 * 1024 * 1024) throw new ChatError('too_large');
      buffer += decoder.decode(chunk.value, {stream: true});
      let index: number;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const result = line(buffer.slice(0, index)); buffer = buffer.slice(index + 1);
        if (result) return result;
      }
      if (buffer.length > 1024 * 1024) throw new ChatError('too_large');
    }
  } finally {void reader.cancel().catch(() => {}); reader.releaseLock();}
}
export async function streamChat(base: string, token: string, prompt: string, signal: AbortSignal, onDelta: (delta: string) => void, fetcher: typeof fetch = fetch): Promise<Receipt> {
  if (!prompt.trim() || byteLength(prompt) > MAX_PROMPT_BYTES) throw new ChatError('too_large');
  const options = requestOptions(token, signal);
  const response = await fetcher(gatewayBase(base) + '/api/v1/ai/responses', {...options, method: 'POST', headers: {...options.headers, 'Content-Type': 'application/json', Accept: 'text/event-stream'}, body: JSON.stringify({prompt})});
  if (!response.ok) throw statusError(response.status);
  if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'text/event-stream' || !response.body) throw new ChatError('protocol');
  return readChatStream(response.body, onDelta);
}

