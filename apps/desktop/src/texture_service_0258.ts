/** 0.25.8: account-scoped local texture operations; never sends official credentials. */
export type TextureKind0258 = 'skin' | 'cape';
export type SkinModel0258 = 'classic' | 'slim';
export type TextureVisibility0258 = 'public' | 'unlisted' | 'private';
export type TextureAssignment0258 = {
  id: number; realm: string; profileUuid: string; projectId: string; kind: TextureKind0258;
  blobDigest?: string; externalUrl?: string; model: SkinModel0258; visibility: TextureVisibility0258;
  revision: number; active: boolean; updatedAt: string;
};
export type TextureItem0258 = {
  digest: string; kind: TextureKind0258; model: SkinModel0258; source: string;
  bytes: number; width: number; height: number; createdAt: string; lastSelectedAt?: string;
};
export type TextureIdentity0258 = {realm: string; profileUuid: string; profileName: string; items: TextureAssignment0258[]};
export type TextureHistory0258 = {revision: number; event: string; createdAt: string; snapshot?: Record<string, unknown>};

export class TextureServiceError0258 extends Error {
  constructor(public readonly status: number, message: string) { super(message); this.name = 'TextureServiceError0258'; }
}

export function textureAssignment0258(items: TextureAssignment0258[], kind: TextureKind0258): TextureAssignment0258 | undefined {
  return items.find(item => item.kind === kind && item.projectId === '');
}
export function textureRevision0258(items: TextureAssignment0258[], kind: TextureKind0258): number {
  return textureAssignment0258(items, kind)?.revision ?? 0;
}
export function validateTextureFile0258(file: Pick<File,'name'|'size'|'type'>): void {
  if (file.size < 1 || file.size > 4*1024*1024) throw new Error('PNG должен иметь размер от 1 байта до 4 МиБ.');
  if (file.type && file.type !== 'image/png') throw new Error('Поддерживаются только PNG-файлы.');
  if (!file.name.toLowerCase().endsWith('.png')) throw new Error('Имя файла должно заканчиваться на .png.');
}
export function safeOfficialTextureURL0258(value: string): string | undefined {
  try {
    const u = new URL(value);
    // Minecraft Services can return http://textures.minecraft.net/texture/<hash>.
    // Upgrade ONLY this public CDN to TLS; all other hosts and arbitrary paths fail closed.
    if (!['https:', 'http:'].includes(u.protocol) || u.hostname !== 'textures.minecraft.net' || u.username || u.password || u.port || u.search || u.hash || !/^\/texture\/[0-9a-f]{20,128}$/i.test(u.pathname)) return undefined;
    u.protocol = 'https:';
    return u.href;
  } catch { return undefined; }
}

function textureError0258(status: number, payload: unknown): TextureServiceError0258 {
  const obj = payload && typeof payload === 'object' ? payload as {error?: {message?: string}} : {};
  const message = obj.error?.message;
  if (status === 409) return new TextureServiceError0258(status, 'Текстура изменена в другой сессии. Список обновлён, повторите действие.');
  if (status === 401) return new TextureServiceError0258(status, 'Сессия истекла. Войдите в NeverLauncher повторно.');
  if (status === 403) return new TextureServiceError0258(status, 'Операция запрещена правами владельца проекта или профиля.');
  if (status === 413) return new TextureServiceError0258(status, 'Файл или квота превышает допустимый размер.');
  return new TextureServiceError0258(status, typeof message === 'string' ? message : `Texture API: HTTP ${status}`);
}
export class TextureServiceClient0258 {
  constructor(private readonly base: string, private readonly token: string) {}
  private url(path: string): string { return `${this.base.replace(/\/+$/, '')}${path}`; }
  private headers(): Record<string,string> { return {Authorization: `Bearer ${this.token}`}; }
  private async json<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
    if (!this.token) throw new TextureServiceError0258(401, 'Войдите в NeverLauncher.');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25_000);
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, {once: true});
    try {
      const res = await fetch(this.url(path), {
        method, cache: 'no-store', redirect: 'error', credentials: 'omit',
        headers: {...this.headers(), ...(body === undefined ? {} : {'Content-Type':'application/json'})},
        body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal,
      });
      const result = await res.json().catch(() => null);
      if (!res.ok) throw textureError0258(res.status, result);
      if (!result || !('data' in result)) throw new Error('Texture API вернул некорректный ответ.');
      return result.data as T;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
    }
  }
  identity(signal?: AbortSignal): Promise<TextureIdentity0258> { return this.json('/api/v1/me/textures', 'GET', undefined, signal); }
  async library(signal?: AbortSignal): Promise<TextureItem0258[]> {
    const data = await this.json<{items: TextureItem0258[]}>('/api/v1/me/textures/library', 'GET', undefined, signal);
    return Array.isArray(data?.items) ? data.items : [];
  }
  history(kind: TextureKind0258, signal?: AbortSignal): Promise<TextureHistory0258[]> {
    return this.json(`/api/v1/me/textures/${kind}/history`, 'GET', undefined, signal);
  }
  select(kind: TextureKind0258, digest: string, revision: number, model: SkinModel0258, visibility: TextureVisibility0258): Promise<TextureAssignment0258> {
    return this.json(`/api/v1/me/textures/${kind}/select`, 'POST', {digest, expectedRevision: revision, model: kind === 'cape' ? 'classic' : model, visibility});
  }
  reset(kind: TextureKind0258, revision: number, remove = false): Promise<TextureAssignment0258> {
    return this.json(`/api/v1/me/textures/${kind}${remove ? '' : '/reset'}`, remove ? 'DELETE' : 'POST', {expectedRevision: revision});
  }
  deleteSaved(kind: TextureKind0258, digest: string): Promise<{deleted: boolean}> {
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('Недопустимый идентификатор PNG.');
    return this.json(`/api/v1/me/textures/library/${kind}/${digest}`, 'DELETE');
  }
  change(kind: TextureKind0258, item: TextureAssignment0258, model: SkinModel0258, visibility: TextureVisibility0258): Promise<TextureAssignment0258> {
    return this.json(`/api/v1/me/textures/${kind}`, 'PATCH', {expectedRevision: item.revision, active: item.active, model: kind === 'cape' ? 'classic' : model, visibility});
  }
  importURL(kind: TextureKind0258, url: string, revision: number, model: SkinModel0258, visibility: TextureVisibility0258): Promise<unknown> {
    return this.json(`/api/v1/me/textures/${kind}/import`, 'POST', {url, expectedRevision: revision, model: kind === 'cape' ? 'classic' : model, visibility});
  }
  /** Never cache owner-only PNG bytes or use the image endpoint as an unauthenticated <img> URL. */
  async preview(kind: TextureKind0258, digest: string, signal?: AbortSignal): Promise<string> {
    if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('Недопустимый идентификатор PNG.');
    const res = await fetch(this.url(`/api/v1/me/textures/library/${kind}/${digest}/image`), {
      headers: this.headers(), cache:'no-store', credentials:'omit', redirect:'error', signal,
    });
    if (!res.ok) throw textureError0258(res.status, await res.json().catch(() => null));
    if (!(res.headers.get('Content-Type') || '').toLowerCase().startsWith('image/png')) throw new Error('Сервер не вернул PNG.');
    const bytes = await res.blob();
    if (bytes.size < 1 || bytes.size > 4 * 1024 * 1024) throw new Error('Неверный размер PNG с сервера.');
    return URL.createObjectURL(bytes);
  }
  /** XHR is used for real upload progress; requests are cancellable on logout/unmount. */
  upload(kind: TextureKind0258, file: File, revision: number, model: SkinModel0258, visibility: TextureVisibility0258,
         onProgress: (percent: number) => void, signal?: AbortSignal): Promise<unknown> {
    validateTextureFile0258(file);
    if (!this.token) return Promise.reject(new TextureServiceError0258(401, 'Войдите в NeverLauncher.'));
    const form = new FormData();
    form.append('file', file, file.name);
    form.append('model', kind === 'cape' ? 'classic' : model);
    form.append('visibility', visibility);
    form.append('expectedRevision', String(revision));
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      let finished = false;
      const dispose = () => signal?.removeEventListener('abort', abort);
      const done = (err?: Error, value?: unknown) => { if (finished) return; finished = true; dispose(); err ? reject(err) : resolve(value); };
      const abort = () => xhr.abort();
      xhr.open('POST', this.url(`/api/v1/me/textures/${kind}/upload`), true);
      xhr.timeout = 40_000;
      xhr.setRequestHeader('Authorization', `Bearer ${this.token}`);
      xhr.upload.onprogress = ev => { if (ev.lengthComputable && ev.total > 0) onProgress(Math.min(99, Math.round(ev.loaded / ev.total * 100))); };
      xhr.onload = () => { const data = (() => { try { return JSON.parse(xhr.responseText); } catch { return null; } })();
        if (xhr.status < 200 || xhr.status >= 300) done(textureError0258(xhr.status, data));
        else if (data?.data) {onProgress(100); done(undefined, data.data);} else done(new Error('Сервер вернул неверный ответ загрузки.'));
      };
      xhr.onerror = () => done(new Error('Ошибка сети при загрузке PNG.'));
      xhr.ontimeout = () => done(new Error('Превышено время загрузки PNG.'));
      xhr.onabort = () => done(new DOMException('Загрузка отменена.', 'AbortError'));
      if (signal?.aborted) {done(new DOMException('Загрузка отменена.', 'AbortError')); return;}
      signal?.addEventListener('abort', abort, {once: true});
      xhr.send(form);
    });
  }
}
