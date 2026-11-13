import { warmAfterIdle03011 } from "./startup_prewarmer";
// Настоящие точки разделения кода Vite: модули не разбираются, пока не открыт их
// экран или лаунчер не простаивает. Один промис импорта на представление
// устраняет дублирование при переходах и предварительном прогреве кэша.
export const desktopViews03011 = {
  extensions: () =>
    import("./extensions").then((m) => ({
      default: m.DesktopExtensions0209,
    })),
  components: () =>
    import("./ComponentChooser").then((m) => ({
      default: m.ComponentChooser0247,
    })),
  portability: () =>
    import("./ComponentPortability").then((m) => ({
      default: m.ComponentPortability02410,
    })),
  official: () =>
    import("./OfficialMinecraftPanel").then((m) => ({
      default: m.OfficialMinecraftPanel0257,
    })),
  textures: () =>
    import("./TexturesPanel").then((m) => ({
      default: m.TexturesPanel0258,
    })),
  deviceRisk: () =>
    import("./HWIDRisk").then((m) => ({ default: m.HWIDRisk0299 })),
};

export type DesktopView03011 = keyof typeof desktopViews03011;
type LoaderResult = { default: unknown };
const loaded = new Map<DesktopView03011, Promise<LoaderResult>>();
export function loadDesktopView03011<T extends DesktopView03011>(
  name: T,
): ReturnType<(typeof desktopViews03011)[T]> {
  const cached = loaded.get(name);
  if (cached) return cached as ReturnType<(typeof desktopViews03011)[T]>;
  const promise = desktopViews03011[name]() as Promise<LoaderResult>;
  loaded.set(name, promise);
  // При ошибке сетевого импорта или загрузки пакета попытку можно повторить при следующем переходе.
  void promise.catch(() => {
    if (loaded.get(name) === promise) loaded.delete(name);
  });
  return promise as ReturnType<(typeof desktopViews03011)[T]>;
}

// Запуск не должен ожидать необязательные страницы. После простоя предварительно загружаются только
// два экрана, чтобы не создавать всплеск выполнения JS при инициализации аутентификации.
export function prewarmDesktop03011(
  options: {
    schedule?: (work: () => void) => () => void;
    warm?: (name: DesktopView03011) => Promise<unknown>;
  } = {},
): () => void {
  const warm = options.warm ?? ((name) => loadDesktopView03011(name));
  const schedule =
    options.schedule ??
    ((work) => {
      if (typeof window !== "undefined" && "requestIdleCallback" in window) {
        const idle = window.requestIdleCallback(work, { timeout: 4000 });
        return () => window.cancelIdleCallback(idle);
      }
      const timer = setTimeout(work, 1800);
      return () => clearTimeout(timer);
    });
  return warmAfterIdle03011(schedule, warm, [
    "official",
    "components",
  ] as const, () => typeof document === "undefined" || document.visibilityState !== "hidden");
}
