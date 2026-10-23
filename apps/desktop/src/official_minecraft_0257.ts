/** Official Minecraft operations never read or write Never/Yggdrasil texture IDs. */
export type OfficialProfile0257 = {
  id: string;
  name: string;
  skins: Array<{id: string; state: string; url: string; variant: string}>;
  capes: Array<{id: string; state: string; url: string; alias?: string}>;
};
export type OfficialDevice0257 = {
  verificationUri: string;
  userCode: string;
  intervalSeconds: number;
  expiresIn: number;
  flow: string;
};
export type OfficialMinecraftCredentials0257 = {
  realm: 'official-minecraft';
  username: string;
  uuid: string;
  accessToken: string;
  userType: 'msa';
  authServerBaseUrl: string;
};

export class OfficialMinecraftClient0257 {
  private flow: string | null = null;
  private session: string | null = null;
  private nextPoll = 0;
  constructor(private backendUrl: string, private neverToken: string) {}
  rebind(backendUrl: string, neverToken: string) {
    if (this.backendUrl !== backendUrl) this.clear();
    this.backendUrl = backendUrl;
    this.neverToken = neverToken;
  }
  clear() { this.session = null; this.flow = null; this.nextPoll = 0; }
  get linked() { return Boolean(this.session); }
  private async request<T>(route: string, method: string, body?: BodyInit, contentType?: string, ticket?: string): Promise<{status: number; data: T}> {
    if (!this.neverToken) throw new Error('Сначала выполните вход в NeverLauncher.');
    const headers: Record<string, string> = {Authorization: `Bearer ${this.neverToken}`};
    if (ticket) headers['X-Official-Minecraft-Session'] = ticket;
    if (contentType) headers['Content-Type'] = contentType;
    const response = await fetch(`${this.backendUrl.replace(/\/$/, '')}${route}`, {method, headers, body, cache: 'no-store'});
    const rotated = response.headers.get('X-Official-Minecraft-Session');
    if (rotated && this.session) this.session = rotated;
    const payload = await response.json().catch(() => null);
    if (!response.ok && response.status !== 202) throw new Error(payload?.error?.message || `Minecraft Services: ${response.status}`);
    return {status: response.status, data: (payload?.data ?? payload) as T};
  }
  async begin(): Promise<OfficialDevice0257> {
    this.clear();
    const {data} = await this.request<OfficialDevice0257>('/api/v1/minecraft/official/device/start', 'POST');
    if (!data?.flow || !data.userCode || !data.verificationUri) throw new Error('Microsoft вернул неполные данные авторизации.');
    this.flow = data.flow;
    this.nextPoll = Date.now() + data.intervalSeconds * 1000;
    return data;
  }
  async poll(): Promise<{pending: boolean; profile?: OfficialProfile0257}> {
    if (!this.flow) throw new Error('Нет незавершённой Microsoft-авторизации.');
    if (Date.now() < this.nextPoll) throw new Error('Запрос выполняется слишком часто.');
    const {status, data} = await this.request<{status?: string; flow?: string; intervalSeconds?: number; profile?: OfficialProfile0257; session?: string}>('/api/v1/minecraft/official/device/poll', 'POST', undefined, undefined, this.flow);
    if (status === 202) {
      if (!data.flow) throw new Error('Сервер не вернул продолжение авторизации.');
      this.flow = data.flow;
      this.nextPoll = Date.now() + Math.max(data.intervalSeconds ?? 5, 5) * 1000;
      return {pending: true};
    }
    if (!data.session || !data.profile?.id) throw new Error('Официальный Minecraft-профиль не подтверждён.');
    this.session = data.session;
    this.flow = null;
    return {pending: false, profile: data.profile};
  }
  private ticket(): string {
    if (!this.session) throw new Error('Подключите официальный аккаунт Minecraft.');
    return this.session;
  }
  async profile(): Promise<OfficialProfile0257> {
    const {data} = await this.request<{profile: OfficialProfile0257}>('/api/v1/minecraft/official/profile', 'GET', undefined, undefined, this.ticket());
    return data.profile;
  }
  async uploadSkin(file: File, variant: 'classic' | 'slim'): Promise<OfficialProfile0257> {
    const form = new FormData(); form.append('variant', variant); form.append('file', file, 'skin.png');
    const {data} = await this.request<{profile: OfficialProfile0257}>('/api/v1/minecraft/official/skin', 'POST', form, undefined, this.ticket());
    return data.profile;
  }
  async resetSkin(): Promise<OfficialProfile0257> {
    const {data} = await this.request<{profile: OfficialProfile0257}>('/api/v1/minecraft/official/skin', 'DELETE', undefined, undefined, this.ticket());
    return data.profile;
  }
  async selectCape(capeId: string): Promise<OfficialProfile0257> {
    const {data} = await this.request<{profile: OfficialProfile0257}>('/api/v1/minecraft/official/cape', 'PUT', JSON.stringify({capeId}), 'application/json', this.ticket());
    return data.profile;
  }
  async resetCape(): Promise<OfficialProfile0257> {
    const {data} = await this.request<{profile: OfficialProfile0257}>('/api/v1/minecraft/official/cape', 'DELETE', undefined, undefined, this.ticket());
    return data.profile;
  }
  async credentials(): Promise<OfficialMinecraftCredentials0257> {
    const {data} = await this.request<OfficialMinecraftCredentials0257>('/api/v1/minecraft/official/launch-credentials', 'POST', undefined, undefined, this.ticket());
    if (data.realm !== 'official-minecraft' || data.userType !== 'msa' || data.authServerBaseUrl !== '' || !data.uuid || !data.accessToken) {
      throw new Error('Некорректная официальная Minecraft identity.');
    }
    return data;
  }
}
