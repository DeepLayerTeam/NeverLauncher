import type {
  OfficialMinecraftClient0257,
  OfficialProfile0257,
  OfficialAccount0267,
  OfficialDevice0257,
  NeverOfficialLink0268,
} from "./official_minecraft_0257";

/** Public, non-sensitive desktop view of the native identity manager. */
export type AuthenticationActivity02610 =
  | "loading"
  | "cancel"
  | "browser"
  | "device"
  | "select"
  | "refresh"
  | "logout"
  | "profile"
  | "link"
  | "unlink"
  | "skin"
  | "cape"
  | null;
export type AuthenticationState02610 = Readonly<{
  accounts: readonly OfficialAccount0267[];
  profile: OfficialProfile0257 | null;
  links: readonly NeverOfficialLink0268[] | null;
  activity: AuthenticationActivity02610;
  device: OfficialDevice0257 | null;
  deviceExpiresAt: number | null;
  issue: string | null;
  linksIssue: string | null;
  initialized: boolean;
}>;
export const initialAuthenticationState02610: AuthenticationState02610 =
  Object.freeze({
    accounts: [],
    profile: null,
    links: null,
    activity: "loading",
    device: null,
    deviceExpiresAt: null,
    issue: null,
    linksIssue: null,
    initialized: false,
  });

/** Never put a raw provider/native exception into the UI (it can contain OAuth query params). */
export function describeAuthenticationFailure02610(error: unknown): string {
  const raw =
    typeof error === "string"
      ? error
      : error instanceof Error
        ? error.message
        : "";
  if (/отмен|cancel|abort/i.test(raw)) return "Операция отменена.";
  if (
    /expired|ист[её]к|invalid.grant|refresh.token|reauth|повторн.*вход/i.test(
      raw,
    )
  )
    return "Срок действия авторизации истёк. Выполните вход Microsoft заново.";
  if (/access.denied|отказ|permission.denied/i.test(raw))
    return "Microsoft отклонил запрос на авторизацию.";
  if (/slow.down|429|rate.limit|слишком много/i.test(raw))
    return "Провайдер ограничил запросы. Повторите попытку позднее.";
  if (
    /invalid.app.registration|app.registration|не.*зарегистрирован|client.id/i.test(
      raw,
    )
  )
    return "Приложение Microsoft не допущено к Minecraft Services. Обратитесь к администратору Launcher.";
  if (/xsts|xbox|family|родител|multiplayer/i.test(raw))
    return "Xbox отклонил авторизацию. Проверьте Xbox-профиль, разрешения Family и доступ к игре.";
  if (
    /entitlement|java.profile|minecraft.profile|игров.*доступ|demo|лиценз|профиль.*не/i.test(
      raw,
    )
  )
    return "Minecraft Java профиль или игровой доступ не подтверждены.";
  if (/uuid|identity.mismatch|подмен/i.test(raw))
    return "Minecraft UUID не совпал с сохранённым аккаунтом. Вход заблокирован.";
  if (/vault|keyring|credential|хранилищ/i.test(raw))
    return "Системное хранилище учётных данных недоступно. Проверьте настройки ОС.";
  if (
    /offline|network|timeout|timed.out|connection|недоступ|503|502|500/i.test(
      raw,
    )
  )
    return "Сервис авторизации временно недоступен. Повторите попытку.";
  if (/не найден|not.found/i.test(raw))
    return "Аккаунт не найден. Обновите список или войдите заново.";
  if (/уже привязан|already.linked|conflict|конфликт/i.test(raw))
    return "Этот Minecraft UUID уже привязан к другому аккаунту.";
  return "Операция с игровым аккаунтом не выполнена. Повторите попытку или проверьте диагностику.";
}

/**
 * Serializes all account mutations and invalidates late OAuth results. Native Rust
 * remains the sole owner of tokens; this class only transports verified profiles.
 */
export class AuthenticationExperience02610 {
  private value: AuthenticationState02610 = initialAuthenticationState02610;
  private listeners = new Set<(state: AuthenticationState02610) => void>();
  private generation = 0;
  private disposed = false;
  constructor(
    private readonly client: OfficialMinecraftClient0257,
    private readonly onProfile: (profile: OfficialProfile0257 | null) => void,
  ) {}
  get snapshot(): AuthenticationState02610 {
    return this.value;
  }
  subscribe(listener: (state: AuthenticationState02610) => void): () => void {
    this.listeners.add(listener);
    listener(this.value);
    return () => this.listeners.delete(listener);
  }
  private update(patch: Partial<AuthenticationState02610>): void {
    if (this.disposed) return;
    this.value = { ...this.value, ...patch };
    for (const listener of this.listeners) listener(this.value);
  }
  private current(token: number): boolean {
    return !this.disposed && token === this.generation;
  }
  private publishProfile(profile: OfficialProfile0257 | null): void {
    if (this.disposed) return;
    this.update({ profile });
    this.onProfile(profile);
  }
  private async collect(
    token: number,
    profile: OfficialProfile0257 | null,
    issue: string | null = null,
  ): Promise<void> {
    // Directory data is local vault metadata. A links Backend outage must not hide playable accounts.
    const [accountsResult, linksResult] = await Promise.allSettled([
      this.client.accounts(),
      this.client.Links(),
    ]);
    if (!this.current(token)) return;
    const accounts =
      accountsResult.status === "fulfilled"
        ? accountsResult.value
        : this.value.accounts;
    const active = accounts.find((account) => account.active);
    // Prevent displaying a stale name/UUID as launch-ready after a native account switch.
    const verified =
      profile && active && profile.id.toLowerCase() === active.id.toLowerCase()
        ? profile
        : null;
    this.update({
      accounts,
      links: linksResult.status === "fulfilled" ? linksResult.value : null,
      linksIssue:
        linksResult.status === "rejected"
          ? "Связь с Never identity временно недоступна."
          : null,
      issue:
        accountsResult.status === "rejected"
          ? describeAuthenticationFailure02610(accountsResult.reason)
          : issue,
      initialized: true,
    });
    this.publishProfile(verified);
  }
  async initialize(): Promise<void> {
    const token = ++this.generation;
    this.update({ activity: "loading", issue: null });
    let profile: OfficialProfile0257 | null = null;
    let issue: string | null = null;
    try {
      profile = await this.client.restore();
    } catch (e) {
      issue = describeAuthenticationFailure02610(e);
    }
    if (!this.current(token)) return;
    try {
      await this.collect(token, profile, issue);
    } catch {
      if (this.current(token)) {
        this.publishProfile(null);
        this.update({
          issue: "Не удалось прочитать игровые аккаунты.",
          initialized: true,
        });
      }
    }
    if (this.current(token)) this.update({ activity: null });
  }
  private async execute<T>(
    activity: Exclude<AuthenticationActivity02610, null | "loading" | "cancel">,
    task: (token: number) => Promise<T>,
  ): Promise<T | undefined> {
    if (this.disposed || this.value.activity !== null) return;
    const token = ++this.generation;
    this.update({ activity, issue: null });
    try {
      return await task(token);
    } catch (e) {
      if (this.current(token))
        this.update({ issue: describeAuthenticationFailure02610(e) });
      return;
    } finally {
      if (this.current(token)) this.update({ activity: null });
    }
  }
  private async accepted(
    token: number,
    profile: OfficialProfile0257 | null,
  ): Promise<void> {
    if (!this.current(token)) return;
    await this.collect(token, profile);
  }
  async browserLogin(): Promise<void> {
    await this.execute("browser", async (token) => {
      const profile = await this.client.browserLogin();
      await this.accepted(token, profile);
    });
  }
  async deviceLogin(): Promise<void> {
    await this.execute("device", async (token) => {
      const device = await this.client.begin();
      if (!this.current(token)) return;
      this.update({
        device,
        deviceExpiresAt: Date.now() + Math.max(0, device.expiresIn) * 1000,
      });
      const profile = await this.client.waitDevice();
      if (this.current(token)) await this.accepted(token, profile);
    });
    // Ignore a stale finally after cancel and a new flow.
    if (!this.disposed && this.value.activity === null)
      this.update({ device: null, deviceExpiresAt: null });
  }
  async cancelLogin(): Promise<void> {
    if (this.value.activity !== "browser" && this.value.activity !== "device")
      return;
    const token = ++this.generation; // synchronous fence, before the awaited IPC operation
    // Keep the UI locked until native cancellation finishes; a new login must not
    // race an in-flight cancellation that could destroy its native flow.
    this.update({
      activity: "cancel",
      device: null,
      deviceExpiresAt: null,
      issue: null,
    });
    try {
      await this.client.cancel();
    } catch (e) {
      if (this.current(token))
        this.update({ issue: describeAuthenticationFailure02610(e) });
    } finally {
      if (this.current(token)) this.update({ activity: null });
    }
  }
  async select(id: string): Promise<void> {
    await this.execute("select", async (token) => {
      if (!this.value.accounts.some((account) => account.id === id))
        throw Error("Аккаунт не найден");
      const profile = await this.client.selectAccount(id);
      await this.accepted(token, profile);
    });
  }
  async refresh(): Promise<void> {
    await this.execute("refresh", async (token) => {
      try {
        const profile = await this.client.refresh();
        await this.accepted(token, profile);
      } catch (e) {
        if (this.current(token)) {
          // A revoked/expired credential must not remain launch-ready.
          this.publishProfile(null);
        }
        throw e;
      }
    });
  }
  async revalidate(): Promise<void> {
    await this.execute("profile", async (token) => {
      try {
        await this.accepted(token, await this.client.profile());
      } catch (e) {
        if (this.current(token)) this.publishProfile(null);
        throw e;
      }
    });
  }
  async logout(id: string): Promise<void> {
    await this.execute("logout", async (token) => {
      try {
        await this.accepted(token, await this.client.logout(id));
      } catch (e) {
        // Local removal can succeed even when the following provider check fails.
        // Do not keep a potentially deleted account launch-ready.
        if (this.current(token)) this.publishProfile(null);
        throw e;
      }
    });
  }
  async link(id: string): Promise<void> {
    await this.execute("link", async (token) => {
      if (this.value.profile?.id.toLowerCase() !== id.toLowerCase())
        throw Error("Minecraft UUID mismatch");
      await this.client.linkToNever(id, true);
      await this.accepted(token, this.value.profile);
    });
  }
  async unlink(id: string): Promise<void> {
    await this.execute("unlink", async (token) => {
      if (this.value.profile?.id.toLowerCase() !== id.toLowerCase())
        throw Error("Minecraft UUID mismatch");
      await this.client.unlinkFromNever(id, true);
      await this.accepted(token, this.value.profile);
    });
  }
  async uploadSkin(file: File, variant: "classic" | "slim"): Promise<void> {
    await this.execute("skin", async (token) => {
      await this.accepted(token, await this.client.uploadSkin(file, variant));
    });
  }
  async resetSkin(): Promise<void> {
    await this.execute("skin", async (token) => {
      await this.accepted(token, await this.client.resetSkin());
    });
  }
  async selectCape(id: string): Promise<void> {
    await this.execute("cape", async (token) => {
      await this.accepted(token, await this.client.selectCape(id));
    });
  }
  async resetCape(): Promise<void> {
    await this.execute("cape", async (token) => {
      await this.accepted(token, await this.client.resetCape());
    });
  }
  dispose(): void {
    const active = this.value.activity;
    this.disposed = true;
    ++this.generation;
    this.listeners.clear();
    if (active === "browser" || active === "device")
      void this.client.cancel().catch(() => {});
  }
}
