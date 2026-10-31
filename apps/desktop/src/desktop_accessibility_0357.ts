/** Persistent player-only UI preferences. These never change signed provisioning or API trust. */
export type Locale0357 = "ru" | "en";
export type UISettings0357 = {
  locale: Locale0357;
  zoom: number;
  reducedMotion: boolean;
  highContrast: boolean;
};
export const UI_PREFERENCES_KEY0357 = "launcher.desktop.ui.0357";
export const ZOOM_LEVELS0357 = [80, 90, 100, 110, 125, 150, 175, 200] as const;
export const SCREENS0357 = [
  "firstRun",
  "overview",
  "auth",
  "projects",
  "profile",
  "download",
  "migration",
  "textures",
  "settings",
  "extensions",
  "logs",
  "diagnostics",
] as const;
export type Screen0357 = (typeof SCREENS0357)[number];

export function selectLocale0357(value: unknown): Locale0357 {
  return value === "en" ? "en" : "ru";
}
export function validateUISettings0357(
  raw: unknown,
  preferredLocale: Locale0357 = "ru",
): UISettings0357 {
  const source =
    raw && typeof raw === "object" && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  return {
    locale:
      source.locale === "en" || source.locale === "ru"
        ? source.locale
        : preferredLocale,
    zoom:
      typeof source.zoom === "number" &&
      ZOOM_LEVELS0357.some((level) => level === source.zoom)
        ? source.zoom
        : 100,
    reducedMotion:
      typeof source.reducedMotion === "boolean" ? source.reducedMotion : false,
    highContrast:
      typeof source.highContrast === "boolean" ? source.highContrast : false,
  };
}
export function nextZoom0357(current: number, direction: -1 | 0 | 1): number {
  if (direction === 0) return 100;
  const levels = ZOOM_LEVELS0357 as readonly number[];
  if (direction > 0)
    return levels.find((x) => x > current) ?? levels[levels.length - 1];
  return [...levels].reverse().find((x) => x < current) ?? levels[0];
}
export function isEditableTarget0357(target: EventTarget | null): boolean {
  if (!target || typeof target !== "object") return false;
  const el = target as HTMLElement;
  const tag = (el.tagName || "").toLowerCase();
  return (
    tag === "input" ||
    tag === "textarea" ||
    tag === "select" ||
    Boolean(el.isContentEditable) ||
    Boolean(el.closest?.('[contenteditable="true"]'))
  );
}
/** Do not hijack text inputs, IME composition or the OS browser's normal shortcuts. */
export function shortcut0357(
  event: {
    key: string;
    ctrlKey: boolean;
    metaKey: boolean;
    altKey: boolean;
    shiftKey: boolean;
    isComposing?: boolean;
    target?: EventTarget | null;
  },
  os: string,
):
  | { type: "zoom"; direction: -1 | 0 | 1 }
  | { type: "section"; index: number }
  | { type: "focusNav" }
  | null {
  if (event.isComposing || event.altKey) return null;
  // F6 is a focus-management key, even if a text field currently has focus.
  if (event.key === "F6" && !event.ctrlKey && !event.metaKey && !event.shiftKey)
    return { type: "focusNav" };
  if (isEditableTarget0357(event.target ?? null)) return null;
  const modifier =
    os === "macos"
      ? event.metaKey && !event.ctrlKey
      : event.ctrlKey && !event.metaKey;
  if (!modifier) return null;
  if (event.key === "0" && !event.shiftKey)
    return { type: "zoom", direction: 0 };
  if (event.key === "+" || event.key === "=" || event.key === "Add")
    return { type: "zoom", direction: 1 };
  if (event.key === "-" || event.key === "_" || event.key === "Subtract")
    return { type: "zoom", direction: -1 };
  if (!event.shiftKey && /^[1-9]$/.test(event.key))
    return { type: "section", index: Number(event.key) - 1 };
  return null;
}
/** Trust-gated access: UI shortcuts must never bypass signed first-run or native verification. */
export function canNavigate0357(
  screen: Screen0357,
  nativeLoaded: boolean,
  bootstrapError: boolean,
  hasSignedBundle: boolean,
  onboardingCompleted: boolean,
): boolean {
  if (screen === "firstRun") return true;
  if (!nativeLoaded || bootstrapError) return false;
  if (hasSignedBundle && !onboardingCompleted) return screen === "auth";
  return true;
}
export function rovingNav0357(
  key: string,
  current: number,
  length: number,
): number | null {
  if (length < 1) return null;
  if (key === "Home") return 0;
  if (key === "End") return length - 1;
  if (key === "ArrowDown" || key === "ArrowRight")
    return (current + 1) % length;
  if (key === "ArrowUp" || key === "ArrowLeft")
    return (current - 1 + length) % length;
  return null;
}
export const STRINGS0357 = {
  ru: {
    skip: "Перейти к содержимому",
    nav: "Основные разделы",
    accessibility: "Доступность",
    language: "Язык интерфейса",
    zoom: "Масштаб интерфейса",
    motion: "Уменьшить анимацию",
    contrast: "Повышенный контраст",
    shortcuts: "Горячие клавиши",
    shortcutHint:
      "F6 — меню; стрелки — выбор раздела; Ctrl/Cmd + 1–9 — переход; Ctrl/Cmd + +/-/0 — масштаб.",
    minimize: "Свернуть окно",
    maximize: "Развернуть/восстановить окно",
    sections: [
      "Первый запуск",
      "Обзор",
      "Вход",
      "Проекты и серверы",
      "Профиль и моды",
      "Загрузки",
      "Миграция",
      "Скины и плащи",
      "Настройки",
      "Расширения",
      "История и логи",
      "Диагностика",
    ],
    desktop: "Игровой лаунчер",
    subtitle:
      "Проверка файлов, восстановление, установка, запуск Minecraft и история запусков.",
    news: "Новости проекта",
    website: "Сайт проекта",
    check: "Полная проверка",
    save: "Сохранить привязку",
    repair: "Восстановить",
    rollback: "Откатить релиз",
    clean: "Очистить лишнее",
    plan: "План запуска",
    play: "Играть",
    export: "Экспорт диагностики",
    loading: "Загрузка экрана…",
    backend: "URL Backend",
    manifest: "URL манифеста",
    directory: "Каталог игры",
    player: "Имя игрока",
    memory: "Память, МБ",
    channel: "Канал",
    firstRun: "Первый запуск",
    back: "Вернуться к первому запуску",
    fatal: "Проверка подписанного bundle не пройдена",
    reinstall:
      "Переустановите сборку владельца с корректным ключом доверия. Ручной ввод ключа запрещён.",
    navStatus: "Раздел",
    nativeScale: "Масштаб экрана ОС",
    os: "Операционная система",
    auto: "Системный",
    languageInfo:
      "Язык и масштаб сохраняются только для этого устройства и не меняют подписанный проект.",
    firstRunLead:
      "Настройки проекта загружены из подписанного владельцем bundle и проверены Desktop. URL и ключи не требуются.",
    firstRunProject: "Проект",
    firstRunProfile: "Профиль",
    firstRunChannel: "Канал",
    firstRunSteps: [
      "Подписанный проект и профиль — проверено",
      "Вход",
      "Требования, Java и Manifest",
      "Выбор сервера / опциональных модов",
      "Установка и проверка файлов",
      "Запуск Minecraft — действие игрока",
    ],
    done: "завершено",
    need: "требуется",
    pending: "ожидает",
    verified: "проверено",
    unverified: "не подтверждено",
    available: "доступен",
    signed: "подписан и проверен",
    signIn: "Войти в аккаунт",
    requirements: "Проверить профиль и требования",
    checking: "Проверка требований…",
    serverMods: "Сервер и компоненты сборки",
    serverLabel: "Сервер",
    noAuto: "Не подключаться автоматически",
    modPreset: "Набор опциональных модов",
    defaultPreset: "Набор по умолчанию",
    detailMods: "Подробный выбор модов",
    install: "Установить и проверить файлы",
    installing: "Установка…",
    installed: "Клиент установлен и проверен",
    installedDetail: "Подписанный Manifest и файлы проверены native runtime.",
    downloadsTitle: "Загрузки и восстановление",
    downloadsLead:
      "Файлы проверяются по подписанному манифесту. Staging, SHA-256 и атомарная публикация выполняются Runtime.",
    verifyFiles: "Проверить файлы",
    downloadMissing: "Скачать недостающие",
    repairFiles: "Восстановить повреждённое",
    rollbackFiles: "Откатить выпуск",
    quarantine: "Карантин лишних файлов",
    pause: "Пауза",
    cancel: "Отменить",
    resume: "Продолжить / повторить",
    retry: "Повторить",
    recommended: "Рекомендуемое действие",
    speed: "Скорость",
    remaining: "Осталось",
    network: "Передано по сети",
    cache: "Кеш",
    currentFile: "Текущий файл",
    publishing: "Идёт атомарная публикация; отмена временно недоступна.",
    verifiedBytes: "Подтверждённые байты загрузки",
    settingsTitle: "Настройки запуска",
    java: "Путь к Java",
    width: "Ширина окна игры",
    height: "Высота окна игры",
    fullscreen: "Полный экран",
    autoEnter: "Автоматическое подключение",
    server: "Сервер профиля",
    noServer: "Без выбранного сервера",
    host: "Публичный игровой адрес",
    port: "Порт",
    offline: "Offline (если разрешён Manifest)",
    sentry:
      "Автоматически отправлять обезличенные ошибки в Sentry (по согласию)",
    discord: "Показывать активность в Discord",
    key: "Закреплённый ключ Ed25519",
    validate: "Проверить настройки",
    checkJava: "Проверить Java",
    openDir: "Открыть каталог клиента",
    updateServers: "Обновить серверы",
    saveCache: "Сохранить подписанный кеш",
    loadCache: "Загрузить offline-кеш",
  },
  en: {
    skip: "Skip to content",
    nav: "Main navigation",
    accessibility: "Accessibility",
    language: "Interface language",
    zoom: "Interface scale",
    motion: "Reduce motion",
    contrast: "High contrast",
    shortcuts: "Keyboard shortcuts",
    shortcutHint:
      "F6 — menu; arrows — choose a section; Ctrl/Cmd + 1–9 — navigate; Ctrl/Cmd + +/-/0 — zoom.",
    minimize: "Minimize window",
    maximize: "Maximize / restore window",
    sections: [
      "First run",
      "Overview",
      "Sign in",
      "Projects & servers",
      "Profile & mods",
      "Downloads",
      "Migration",
      "Skins & capes",
      "Settings",
      "Extensions",
      "History & logs",
      "Diagnostics",
    ],
    desktop: "Game launcher",
    subtitle:
      "File verification, repair, downloads, Minecraft launch and launch history.",
    news: "Project news",
    website: "Project website",
    check: "Full verification",
    save: "Save binding",
    repair: "Repair",
    rollback: "Roll back release",
    clean: "Clean unused files",
    plan: "Launch plan",
    play: "Play",
    export: "Export diagnostics",
    loading: "Loading screen…",
    backend: "Backend URL",
    manifest: "Manifest URL",
    directory: "Game directory",
    player: "Player name",
    memory: "Memory, MB",
    channel: "Channel",
    firstRun: "First run",
    back: "Back to first run",
    fatal: "Signed bundle verification failed",
    reinstall:
      "Reinstall the owner-provided build with the correct trusted key. Manual trust-key entry is not allowed.",
    navStatus: "Section",
    nativeScale: "OS screen scale",
    os: "Operating system",
    auto: "System default",
    languageInfo:
      "Language and scaling are stored on this device only and do not change the signed project.",
    firstRunLead:
      "Project settings were loaded from the owner-signed bundle and independently verified by Desktop. No URL or trust-key entry required.",
    firstRunProject: "Project",
    firstRunProfile: "Profile",
    firstRunChannel: "Channel",
    firstRunSteps: [
      "Signed project and profile — verified",
      "Sign in",
      "Requirements, Java and Manifest",
      "Server / optional mods selection",
      "Installation and file verification",
      "Launch Minecraft — player action",
    ],
    done: "complete",
    need: "required",
    pending: "pending",
    verified: "verified",
    unverified: "unverified",
    available: "available",
    signed: "signed and verified",
    signIn: "Sign in",
    requirements: "Check profile and requirements",
    checking: "Checking requirements…",
    serverMods: "Server and build components",
    serverLabel: "Server",
    noAuto: "Do not connect automatically",
    modPreset: "Optional mod preset",
    defaultPreset: "Default preset",
    detailMods: "Choose individual mods",
    install: "Install and verify files",
    installing: "Installing…",
    installed: "Client installed and verified",
    installedDetail:
      "Signed Manifest and files were verified by native runtime.",
    downloadsTitle: "Downloads and recovery",
    downloadsLead:
      "Files are checked against the signed manifest. Staging, SHA-256 and atomic publishing are performed by Runtime.",
    verifyFiles: "Verify files",
    downloadMissing: "Download missing files",
    repairFiles: "Repair damaged files",
    rollbackFiles: "Roll back release",
    quarantine: "Quarantine unused files",
    pause: "Pause",
    cancel: "Cancel",
    resume: "Resume / retry",
    retry: "Retry",
    recommended: "Recommended action",
    speed: "Speed",
    remaining: "Remaining",
    network: "Transferred over network",
    cache: "Cache",
    currentFile: "Current file",
    publishing:
      "Atomic publishing is running; cancellation is temporarily unavailable.",
    verifiedBytes: "Verified download bytes",
    settingsTitle: "Launch settings",
    java: "Java executable",
    width: "Game window width",
    height: "Game window height",
    fullscreen: "Fullscreen",
    autoEnter: "Connect to server automatically",
    server: "Profile server",
    noServer: "No server selected",
    host: "Public game server",
    port: "Port",
    offline: "Offline (only when Manifest permits)",
    sentry: "Automatically send anonymized Sentry errors (opt-in)",
    discord: "Show Discord activity",
    key: "Pinned Ed25519 key",
    validate: "Validate settings",
    checkJava: "Check Java",
    openDir: "Open game directory",
    updateServers: "Refresh servers",
    saveCache: "Save signed cache",
    loadCache: "Load offline cache",
  },
} as const;
export function tr0357(locale: Locale0357) {
  return STRINGS0357[locale];
}
