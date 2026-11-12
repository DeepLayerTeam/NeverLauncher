/** Официальный интерфейс Minecraft версии 0.26.2. Только нативный модуль Tauri
 * может хранить билеты сеанса, токены обновления Microsoft и доступа Minecraft.
 * Интерфейс получает метаданные профиля, отображаемые параметры Device Code и статус,
 * но не учётные данные.
 */
export type OfficialProfile0257 = {
  id: string;
  name: string;
  skins: Array<{ id: string; state: string; url: string; variant: string }>;
  capes: Array<{ id: string; state: string; url: string; alias?: string }>;
};
export type LauncherOfficialLink0268 = {
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
    private Token: string,
    private SessionId: string,
    private readonly native: NativeOfficialInvoke0262,
  ) {}
  rebind(backendUrl: string, Token: string, rSessionId: string) {
    if (this.backendUrl !== backendUrl || this.SessionId !== SessionId)
      this.clear();
    this.backendUrl = backendUrl;
    this.Token = Token;
    this.SessionId = SessionId;
  }
  private get context(): Record<string, string> {
    if (!this.Token || !this.SessionId)
      throw new Error("Сначала выполните вход в Launcher.");
    return {
      backendUrl: this.backendUrl,
      Token: this.Token,
      SessionId: this.SessionId,
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
    // Здесь не запускаются асинхронные команды: begin() не должен конфликтовать с запоздалой отменой.
    // Старые сценарии истекают в нативном модуле либо отменяются через cancel().
  }
  get linked() {
    return this.active;
  }
  /** Восстановление проверяет зашифрованный билет бэкенда и официальный UUID на сервере. */
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
    this.active = hadLinkedAccount; // отмена добавления аккаунта не завершает сеанс уже подключённого аккаунта
    await this.native("official_identity_cancel_0262", {
      backendUrl: this.backendUrl,
      SessionId: this.SessionId,
    });
  }
  /** OAuth PKCE в системном браузере: код авторизации и verifier не должны попадать в React. */
  async browserLogin(): Promise<OfficialProfile0257> {
    const beforeCancel = this.generation;
    await this.cancel();
    // Пользовательская отмена, совпавшая с нативной отменой, не должна запускать новый вход через браузер.
    if (this.generation !== beforeCancel + 1)
      throw new Error("Авторизация отменена.");
    const generation = this.generation;
    const profile = await this.call<OfficialProfile0257>(
      "official_identity_browser_login_0263",
    );
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    if (!profile?.id || !profile.name)
      throw new Error("Microsoft-вход не подтвердил профиль Minecraft Java.");
    this.active = true;
    return profile;
  }
  async begin(): Promise<OfficialDevice0257> {
    const beforeCancel = this.generation;
    await this.cancel();
    // Не позволяем отменённому вызову begin создавать новый процесс Device Code.
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
      throw new Error("Соблюдайте интервал между запросами авторизации по коду устройства Microsoft.");
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
  /** Опрос Device Code, задержки повторов и отмену полностью выполняет Rust.
   * Через IPC передаётся только подтверждённый профиль Minecraft после завершения входа. */
  async waitDevice(): Promise<OfficialProfile0257> {
    const generation = this.generation;
    let profile: OfficialProfile0257;
    try {
      profile = await this.call<OfficialProfile0257>(
        "official_identity_wait_device_0264",
      );
    } catch (cause) {
      // Tauri может отклонить запрос строковым значением. Запоздалый отказ старого
      // процесса не должен отменять недавно запущенный процесс.
      if (generation !== this.generation)
        throw new Error("Авторизация отменена.");
      throw cause instanceof Error ? cause : new Error(String(cause));
    }
    if (generation !== this.generation)
      throw new Error("Авторизация отменена.");
    if (!profile?.id || !profile.name)
      throw new Error("Профиль Minecraft Java не подтверждён.");
    this.active = true;
    return profile;
  }
  async profile(): Promise<OfficialProfile0257> {
    const profile = await this.restore();
    if (!profile) throw new Error("Подключите официальный Minecraft-аккаунт.");
    return profile;
  }
  /** Каталог содержит только метаданные: учётные данные не покидают хранилище ОС под управлением Rust. */
  async accounts(): Promise<OfficialAccount0267[]> {
    return this.call("official_identity_accounts_0267");
  }
  /** Аккаунт становится активным только после проверки профиля поставщика и UUID в Rust. */
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
  /** Явное обновление refresh-токена Microsoft и повторная проверка Java-профиля. */
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
  /** Выход удаляет нативные учётные данные выбранного UUID, не затрагивая остальные аккаунты. */
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
  /** Официальное изменение считается завершённым только при совпадении проверенного
   * нативного аккаунта и состояния, возвращённого Minecraft Services. Интерфейс
   * не формирует запрос поставщика, не сохраняет bearer-токен и не может переключить
   * аккаунт, пока нативная операция удерживает блокировку хранилища. */
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
    // После начала нативной записи AbortSignal не отменяет серверное изменение.
      // Всегда возвращаем подтверждённый результат, а не заявляем о несуществующем откате.
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
  /** Постоянные связи с Minecraft независимо проверяются бэкендом. */
  async Links(): Promise<LauncherOfficialLink0268[]> {
    return this.call<LauncherOfficialLink0268[]>("official_identity_links_0268");
  }
  async linkToLauncher(
    accountId: string,
    confirmed: boolean,
  ): Promise<LauncherOfficialLink0268> {
    if (!confirmed) throw new Error("Требуется подтверждение привязки.");
    return this.call<LauncherOfficialLink0268>("official_identity_link_0268", {
      accountId,
      confirmed: true,
    });
  }
  async unlinkFromLauncher(accountId: string, confirmed: boolean): Promise<void> {
    if (!confirmed) throw new Error("Требуется подтверждение отвязывания.");
    await this.call<void>("official_identity_unlink_0268", {
      accountId,
      confirmed: true,
    });
  }
  /** Намеренно запрещено передавать токены доступа к игре через интерфейс. */
  async credentials(): Promise<never> {
    throw new Error(
      "Учётные данные официального запуска Minecraft доступны только Runtime через нативный менеджер.",
    );
  }
}
