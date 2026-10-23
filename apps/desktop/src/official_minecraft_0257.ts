/** 0.26.2 official Minecraft facade. Only native Tauri is allowed to hold official
 * session tickets/Microsoft refresh/Minecraft access tokens. Renderer receives
 * profile metadata, Device Code display values and status, never credentials.
 */
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
};
export type NativeOfficialInvoke0262 = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

export class OfficialMinecraftClient0257 {
  private active = false;
  private nextPoll = 0;
  private generation = 0;
  constructor(private backendUrl: string, private neverToken: string, private neverSessionId: string,
              private readonly native: NativeOfficialInvoke0262) {}
  rebind(backendUrl: string, neverToken: string, neverSessionId: string) {
    if (this.backendUrl !== backendUrl || this.neverSessionId !== neverSessionId) this.clear();
    this.backendUrl = backendUrl;
    this.neverToken = neverToken;
    this.neverSessionId = neverSessionId;
  }
  private get context(): Record<string,string> {
    if (!this.neverToken || !this.neverSessionId) throw new Error('Сначала выполните вход в NeverLauncher.');
    return {backendUrl: this.backendUrl, neverToken: this.neverToken, neverSessionId: this.neverSessionId};
  }
  private async call<T>(command: string, extra: Record<string,unknown> = {}): Promise<T> {
    return this.native<T>(command, {context: this.context, ...extra});
  }
  clear() {
    this.generation++;
    this.active = false;
    this.nextPoll = 0;
    // No async command is fired here: begin() must not race a delayed cancel.
    // Old flows expire natively or can be explicitly cancelled by cancel().
  }
  get linked() { return this.active; }
  /** Restore validates the encrypted backend ticket and official UUID server-side. */
  async restore(): Promise<OfficialProfile0257|null> {
    const generation = this.generation;
    const profile = await this.call<OfficialProfile0257|null>('official_identity_status_0262');
    if (generation !== this.generation) return null;
    this.active = Boolean(profile);
    return profile;
  }
  async cancel(): Promise<void> {
    this.clear();
    await this.native('official_identity_cancel_0262', {backendUrl:this.backendUrl, neverSessionId:this.neverSessionId});
  }
  async begin(): Promise<OfficialDevice0257> {
    await this.cancel();
    const generation = this.generation;
    const challenge = await this.call<OfficialDevice0257>('official_identity_begin_0262');
    if (generation !== this.generation) throw new Error('Авторизация отменена.');
    this.nextPoll = Date.now() + Math.max(challenge.intervalSeconds,5)*1000;
    return challenge;
  }
  async poll(): Promise<{pending:boolean;profile?:OfficialProfile0257}> {
    if (Date.now() < this.nextPoll) throw new Error('Соблюдайте интервал Microsoft Device Code.');
    const generation = this.generation;
    const result = await this.call<{pending:boolean;profile?:OfficialProfile0257;intervalSeconds?:number}>('official_identity_poll_0262');
    if (generation !== this.generation) throw new Error('Авторизация отменена.');
    if (result.pending) this.nextPoll = Date.now() + Math.max(result.intervalSeconds ?? 5,5)*1000;
    else { if (!result.profile?.id) throw new Error('Не удалось подтвердить официальный профиль.'); this.active = true; }
    return result;
  }
  async profile(): Promise<OfficialProfile0257> {
    const profile = await this.restore();
    if (!profile) throw new Error('Подключите официальный Minecraft-аккаунт.');
    return profile;
  }
  async disconnect(): Promise<void> {
    this.clear();
    await this.native('official_identity_disconnect_0262', {backendUrl:this.backendUrl, neverSessionId:this.neverSessionId});
  }
  async uploadSkin(file: File, variant: 'classic'|'slim', onProgress?: (percent:number)=>void, signal?:AbortSignal): Promise<OfficialProfile0257> {
    if (signal?.aborted) throw new DOMException('Загрузка отменена.', 'AbortError');
    if (file.size<1 || file.size>4*1024*1024 || !file.name.toLowerCase().endsWith('.png') || (file.type && file.type!=='image/png')) throw new Error('Требуется PNG не более 4 МиБ.');
    const buffer = new Uint8Array(await file.arrayBuffer());
    if (signal?.aborted) throw new DOMException('Загрузка отменена.', 'AbortError');
    // The file is not an OAuth secret. Still validate bytes before crossing IPC.
    if (buffer[0]!==137 || buffer[1]!==80 || buffer[2]!==78 || buffer[3]!==71) throw new Error('Недопустимый PNG.');
    const result = await this.call<OfficialProfile0257>('official_identity_texture_0262', {operation:'uploadSkin',skinBytes:Array.from(buffer),variant});
    if (signal?.aborted) throw new DOMException('Загрузка отменена.', 'AbortError');
    onProgress?.(100);
    return result;
  }
  async resetSkin():Promise<OfficialProfile0257> { return this.call('official_identity_texture_0262',{operation:'resetSkin'}); }
  async selectCape(capeId:string):Promise<OfficialProfile0257> { return this.call('official_identity_texture_0262',{operation:'selectCape',capeId}); }
  async resetCape():Promise<OfficialProfile0257> { return this.call('official_identity_texture_0262',{operation:'resetCape'}); }
  /** Intentional break: never return game access tokens through renderer. */
  async credentials():Promise<never> { throw new Error('Official Minecraft launch credentials доступны только NeverRuntime через native manager.'); }
}
