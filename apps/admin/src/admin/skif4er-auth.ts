// The provider ID is shared with Desktop: canonical identity is never keyed by client or UI.
export const issuer = 'https://id.skif4er.ru/realms/skif4er';
export const callbackPath = '/auth/skif4er/callback';
export const pendingKey = 'launcher.admin.skif4er.pending';
export const oidcPath = '/api/v1/auth/oidc/skif4er-id';
export const linkPath = '/api/v1/auth/providers/skif4er-id/link';
export type Mode = 'login' | 'link';
export type Begin = { authorizationUrl: string; state: string; transaction: string; expiresAt: string };
export type Pending = { mode: Mode; backend: string; state: string; transaction: string; expires: number; sessionId: string };
export function secureBackend(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('Для SkiF4er ID требуется корневой HTTPS URL Backend.');
  return u.origin;
}
export function prepare(begin: Begin, backend: string, mode: Mode, sessionId: string, origin: string, now = Date.now()): { pending: Pending; url: string } {
  const url = new URL(begin.authorizationUrl);
  const expires = Date.parse(begin.expiresAt);
  const exact = (name: string, value: string) => url.searchParams.getAll(name).length === 1 && url.searchParams.get(name) === value;
  const single = (name: string, min: number) => url.searchParams.getAll(name).length === 1 && (url.searchParams.get(name)?.length ?? 0) >= min;
  if (url.origin !== new URL(issuer).origin || url.pathname !== new URL(issuer).pathname + '/protocol/openid-connect/auth' || url.username || url.password || url.hash || begin.state.length < 32 || !begin.transaction || !Number.isFinite(expires) || expires <= now || expires > now + 11 * 60_000 || !exact('state', begin.state) || !exact('redirect_uri', origin + callbackPath) || !exact('code_challenge_method', 'S256') || !single('code_challenge', 43) || !single('nonce', 32) || !single('client_id', 1) || !exact('response_type', 'code') || (mode === 'link' && (!sessionId || !exact('prompt', 'login')))) throw new Error('Некорректная транзакция SkiF4er ID.');
  return { pending: { mode, backend: secureBackend(backend), state: begin.state, transaction: begin.transaction, expires, sessionId }, url: url.href };
}
export function consume(storage: Pick<Storage, 'getItem' | 'removeItem'>, href: string, backend: string, sessionId: string, now = Date.now()) {
  const url = new URL(href);
  if (url.pathname !== callbackPath) return null;
  const raw = storage.getItem(pendingKey);
  storage.removeItem(pendingKey); // consume even on failure; never retry an exchanged code
  if (!raw) throw new Error('Транзакция SkiF4er ID отсутствует или уже использована.');
  const p: Pending = JSON.parse(raw);
  const q = url.searchParams;
  if (!p || !['login','link'].includes(p.mode) || p.backend !== secureBackend(backend) || !Number.isFinite(p.expires) || p.expires <= now || !p.transaction || !p.state || q.getAll('state').length !== 1 || q.get('state') !== p.state || q.getAll('iss').length > 1 || (q.has('iss') && q.get('iss') !== issuer) || q.getAll('code').length > 1 || q.getAll('error').length > 1 || (q.has('code') && q.has('error')) || (p.mode === 'link' ? !sessionId || p.sessionId !== sessionId : !!sessionId || !!p.sessionId)) throw new Error('Контекст callback SkiF4er ID не совпадает.');
  if (q.has('error')) throw new Error('Авторизация SkiF4er ID отменена или отклонена.');
  const code = q.get('code');
  if (!code) throw new Error('Код авторизации отсутствует.');
  return { mode: p.mode, body: { code, state: p.state, transaction: p.transaction, deviceId: 'admin-browser' } };
}

// Only a routing hint: the Backend still verifies every signature and session.
export function accessExpired(token: string, now = Date.now()): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || parts[1].length > 32768) return false;
    const {exp} = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return Number.isFinite(exp) && exp * 1000 <= now;
  } catch { return false; }
}
