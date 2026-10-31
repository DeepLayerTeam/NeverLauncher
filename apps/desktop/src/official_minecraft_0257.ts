/** 0.26.2 official Minecraft facade. Only native Tauri is allowed to hold official
 * session tickets/Microsoft refresh/Minecraft access tokens. Renderer receives
 * profile metadata, Device Code display values and status, never credentials.
 */
export type OfficialProfile0257 = {
  id: string;
  name: string;
  skins: Array<{ id: string; state: string; url: string; variant: string }>;
  capes: Array<{ id: string; state: string; url: string; alias?: string }>;
};
export type NeverOfficialLink0268 = {
  minecraftUuid: string;
  minecraftName: string;
  verifiedAt: string;
};
export type OfficialAccount0267 = { id: string; name: string; active: boolean };
export type OfficialDevice0257 = {
  verificationUri: string;
  userCode: string;
  intervalSeconds: number;
  expiresIn: number;
};
export type NativeOfficialInvoke0262 = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

export class OfficialMinecraftClient0257 {
  private active = false;
  private nextPoll = 0;
  private generation = 0;
  constructor(
    private backendUrl: string,
    private neverToken: string,
    private neverSessionId: string,
    private readonly native: NativeOfficialInvoke0262,
  ) {}
  rebind(backendUrl: string, neverToken: string, neverSessionId: string) {
    if (
      this.backendUrl !== backendUrl ||
      this.neverSessionId !== neverSessionId
    )
      this.clear();
    this.backendUrl = backendUrl;
    this.neverToken = neverToken;
    this.neverSessionId = neverSessionId;
  }
  private get context(): Record<string, string> {
    if (!this.neverToken || !this.neverSessionId)
      throw new Error("Сначала выполните вход в Launcher.");
    return {
      backendUrl: this.backendUrl,
      neverToken: this.neverToken,
      neverSessionId: this.neverSessionId,
    };
  }
  private async call<T>(
    command: string,
    extra: Record<string, unknown> = {},
  ): Promise<T> {
    return this.native<T>(command, { context: this.context, ...extra });
  }
  clear() {
    this.generation++;
    this.active = false;
    this.nextPoll = 0;
    // No async command is fired here: begin() must not race a delayed cancel.
    // Old flows expire natively or can be explicitly cancelled by cancel().
  }
  get linked() {
    return this.active;
  }
  /** Restore validates the encrypted backend ticket and official UUID server-side. */
  async restore(): Promise<OfficialProfile0257 | null> {
    const generation = this.generation;
    const profile = await this.call<OfficialProfile0257 | null>(
      "official_identity_status_0262",
    );
    if (generation !== this.generation) return null;
    this.active = Boolean(profile);
    return profile;
  }
  async cancel(): Promise<void> {
    const hadLinkedAccount = this.active;
    this.clear();
    this.active = hadLinkedAccount; // cancelling an add-account flow does not sign out an existing account
    await this.native("official_identity_cancel_0262", {
      backendUrl: this.backendUrl,
      neverSessionId: this.neverSessionId,
    });
  }
  /** System-browser OAuth PKCE: authorization code and verifier never enter React. */
  async browserLogin(): Promise<OfficialProfile0257> {
    const beforeCancel = this.generation;
    await this.cancel();
    // A user cancellation racing with native cancel must not start a new browser flow.
    if (this.generation !== beforeCancel + 1)
      throw new Error("Авторизация отменена.");
    const generation = this.generation;
    const profile = await this.call<OfficialProfile0257>(
      "official_identity_browser_login_0263",
    );
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    if (!profile?.id || !profile.name)
      throw new Error("Microsoft-вход не подтвердил Minecraft Java профиль.");
    this.active = true;
    return profile;
  }
  async begin(): Promise<OfficialDevice0257> {
    const beforeCancel = this.generation;
    await this.cancel();
    // Prevent a cancelled pending begin from creating a new Device Code flow.
    if (this.generation !== beforeCancel + 1)
      throw new Error("Авторизация отменена.");
    const generation = this.generation;
    const challenge = await this.call<OfficialDevice0257>(
      "official_identity_begin_0262",
    );
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    this.nextPoll = Date.now() + Math.max(challenge.intervalSeconds, 5) * 1000;
    return challenge;
  }
  async poll(): Promise<{ pending: boolean; profile?: OfficialProfile0257 }> {
    if (Date.now() < this.nextPoll)
      throw new Error("Соблюдайте интервал Microsoft Device Code.");
    const generation = this.generation;
    const result = await this.call<{
      pending: boolean;
      profile?: OfficialProfile0257;
      intervalSeconds?: number;
    }>("official_identity_poll_0262");
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    if (result.pending)
      this.nextPoll =
        Date.now() + Math.max(result.intervalSeconds ?? 5, 5) * 1000;
    else {
      if (!result.profile?.id)
        throw new Error("Не удалось подтвердить официальный профиль.");
      this.active = true;
    }
    return result;
  }
  /** Rust owns all Device Code polling, retry delays and cancellation.
   * Only a completed, verified Minecraft profile crosses IPC. */
  async waitDevice(): Promise<OfficialProfile0257> {
    const generation = this.generation;
    let profile: OfficialProfile0257;
    try {
      profile = await this.call<OfficialProfile0257>(
        "official_identity_wait_device_0264",
      );
    } catch (cause) {
      // Tauri may reject with a string. Invalidate a late rejection from an
      // older flow rather than allowing it to dismiss a newly started flow.
      if (generation !== this.generation)
        throw new Error("Авторизация отменена.");
      throw cause instanceof Error ? cause : new Error(String(cause));
    }
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    if (!profile?.id || !profile.name)
      throw new Error("Minecraft Java профиль не подтверждён.");
    this.active = true;
    return profile;
  }
  async profile(): Promise<OfficialProfile0257> {
    const profile = await this.restore();
    if (!profile) throw new Error("Подключите официальный Minecraft-аккаунт.");
    return profile;
  }
  /** Metadata-only directory: credentials never leave the Rust OS vault. */
  async accounts(): Promise<OfficialAccount0267[]> {
    return this.call("official_identity_accounts_0267");
  }
  /** A selection becomes active only after Rust validates the provider profile/UUID. */
  async selectAccount(accountId: string): Promise<OfficialProfile0257> {
    const generation = ++this.generation;
    const profile = await this.call<OfficialProfile0257>(
      "official_identity_select_0267",
      { accountId },
    );
    if (generation !== this.generation)
      throw new Error("Переключение аккаунта отменено.");
    this.active = true;
    return profile;
  }
  /** Explicit Microsoft refresh-token rotation and Java profile revalidation. */
  async refresh(): Promise<OfficialProfile0257> {
    const generation = this.generation;
    const profile = await this.call<OfficialProfile0257>(
      "official_identity_refresh_0267",
    );
    if (generation !== this.generation)
      throw new Error("Обновление аккаунта отменено.");
    this.active = true;
    return profile;
  }
  /** Logout deletes one selected UUID's native credential, never all linked accounts. */
  async logout(accountId: string): Promise<OfficialProfile0257 | null> {
    ++this.generation;
    this.active = false;
    await this.call("official_identity_logout_0267", { accountId });
    return this.restore();
  }
  async disconnect(): Promise<void> {
    this.clear();
    await this.call("official_identity_disconnect_0262");
  }
  /** An official change is complete only with a matching, verified native
   * account and the state returned by Minecraft Services. The renderer never
   * constructs a provider request, never persists a bearer, and cannot choose
   * a different account while the native mutation holds its vault lock. */
  private async texture(
    operation: "uploadSkin" | "resetSkin" | "selectCape" | "resetCape",
    extras: Record<string, unknown> = {},
    variant?: "classic" | "slim",
  ): Promise<OfficialProfile0257> {
    const generation = this.generation;
    const current = await this.profile();
    const capeId =
      operation === "selectCape" ? String(extras.capeId || "") : "";
    if (
      capeId &&
      (!/^[a-zA-Z0-9_-]{1,128}$/.test(capeId) ||
        !current.capes.some((c) => c.id === capeId))
    )
      throw new Error(
        "Плащ не принадлежит выбранному официальному Minecraft-аккаунту.",
      );
    const updated = await this.call<OfficialProfile0257>(
      "official_identity_texture_0262",
      { operation, ...extras },
    );
    if (generation !== this.generation)
      throw new Error(
        "Официальный аккаунт изменился во время операции; проверьте профиль.",
      );
    if (!updated || updated.id.toLowerCase() !== current.id.toLowerCase())
      throw new Error(
        "Minecraft Services вернул другой UUID. Изменение не подтверждено.",
      );
    if (
      operation === "selectCape" &&
      !updated.capes?.some((c) => c.id === capeId && c.state === "ACTIVE")
    )
      throw new Error(
        "Minecraft Services не подтвердил выбранный плащ. Обновите профиль.",
      );
    if (
      operation === "resetCape" &&
      updated.capes?.some((c) => c.state === "ACTIVE")
    )
      throw new Error(
        "Minecraft Services не подтвердил снятие плаща. Обновите профиль.",
      );
    if (
      operation === "uploadSkin" &&
      !updated.skins?.some(
        (s) => s.state === "ACTIVE" && s.variant?.toLowerCase() === variant,
      )
    )
      throw new Error(
        "Minecraft Services не подтвердил модель нового скина. Обновите профиль.",
      );
    return updated;
  }
  async uploadSkin(
    file: File,
    variant: "classic" | "slim",
    onProgress?: (percent: number) => void,
    signal?: AbortSignal,
  ): Promise<OfficialProfile0257> {
    if (signal?.aborted)
      throw new DOMException("Загрузка отменена.", "AbortError");
    if (
      file.size < 33 ||
      file.size > 4 * 1024 * 1024 ||
      !file.name.toLowerCase().endsWith(".png") ||
      (file.type && file.type !== "image/png")
    )
      throw new Error("Требуется PNG не более 4 МиБ.");
    const buffer = new Uint8Array(await file.arrayBuffer());
    if (signal?.aborted)
      throw new DOMException("Загрузка отменена.", "AbortError");
    const view = new DataView(
      buffer.buffer,
      buffer.byteOffset,
      buffer.byteLength,
    );
    if (
      buffer[0] !== 137 ||
      buffer[1] !== 80 ||
      buffer[2] !== 78 ||
      buffer[3] !== 71 ||
      buffer[4] !== 13 ||
      buffer[5] !== 10 ||
      buffer[6] !== 26 ||
      buffer[7] !== 10 ||
      view.getUint32(8) !== 13 ||
      String.fromCharCode(...buffer.slice(12, 16)) !== "IHDR" ||
      view.getUint32(16) !== 64 ||
      (view.getUint32(20) !== 64 &&
        !(view.getUint32(20) === 32 && variant === "classic"))
    )
      throw new Error(
        "Официальный Minecraft принимает скин PNG 64×64 или Classic 64×32.",
      );
    // Once the native write starts, AbortSignal cannot undo a server-side
    // change. Always return its verified result rather than claiming rollback.
    const result = await this.texture(
      "uploadSkin",
      { skinBytes: Array.from(buffer), variant },
      variant,
    );
    onProgress?.(100);
    return result;
  }
  async resetSkin(): Promise<OfficialProfile0257> {
    return this.texture("resetSkin");
  }
  async selectCape(capeId: string): Promise<OfficialProfile0257> {
    return this.texture("selectCape", { capeId });
  }
  async resetCape(): Promise<OfficialProfile0257> {
    return this.texture("resetCape");
  }
  /** Durable Never-to-Minecraft links are verified independently by the Backend. */
  async neverLinks(): Promise<NeverOfficialLink0268[]> {
    return this.call<NeverOfficialLink0268[]>("official_identity_links_0268");
  }
  async linkToNever(
    accountId: string,
    confirmed: boolean,
  ): Promise<NeverOfficialLink0268> {
    if (!confirmed) throw new Error("Требуется подтверждение привязки.");
    return this.call<NeverOfficialLink0268>("official_identity_link_0268", {
      accountId,
      confirmed: true,
    });
  }
  async unlinkFromNever(accountId: string, confirmed: boolean): Promise<void> {
    if (!confirmed) throw new Error("Требуется подтверждение отвязывания.");
    await this.call<void>("official_identity_unlink_0268", {
      accountId,
      confirmed: true,
    });
  }
  /** Intentional break: never return game access tokens through renderer. */
  async credentials(): Promise<never> {
    throw new Error(
      "Official Minecraft launch credentials доступны только Runtime через native manager.",
    );
  }
}
