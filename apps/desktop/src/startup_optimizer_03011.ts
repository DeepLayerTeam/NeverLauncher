import { warmAfterIdle03011 } from "./startup_prewarmer_03011";
// Actual Vite code-splitting entrypoints: these modules are not parsed until
// their screen opens or the launcher is idle. One import promise per view
// deduplicates screen navigation and speculative cache warming.
export const desktopViews03011 = {
  extensions: () =>
    import("./extensions_0209").then((m) => ({
      default: m.DesktopExtensions0209,
    })),
  components: () =>
    import("./ComponentChooser0247").then((m) => ({
      default: m.ComponentChooser0247,
    })),
  portability: () =>
    import("./ComponentPortability02410").then((m) => ({
      default: m.ComponentPortability02410,
    })),
  official: () =>
    import("./OfficialMinecraftPanel0257").then((m) => ({
      default: m.OfficialMinecraftPanel0257,
    })),
  textures: () =>
    import("./TexturesPanel0258").then((m) => ({
      default: m.TexturesPanel0258,
    })),
  deviceRisk: () =>
    import("./HWIDRisk0299").then((m) => ({ default: m.HWIDRisk0299 })),
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
  // Failed network/bundle import is retryable when a new navigation happens.
  void promise.catch(() => {
    if (loaded.get(name) === promise) loaded.delete(name);
  });
  return promise as ReturnType<(typeof desktopViews03011)[T]>;
}

// Startup must await optional pages. Only two screens are prefetched after
// idle, preventing a burst of JS evaluation while authentication is initializing.
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
  ] as const);
}
