// Actual Launcher startup state, not an invented percentage or optimistic ready flag.
// Operations update Stage in the Native/Backend UI flow; this view only describes it.
export type StartupStage0427 =
  | "idle" | "connecting" | "session" | "project" | "profile"
  | "manifest" | "java" | "files" | "repair" | "cleanup"
  | "ready" | "launching" | "running" | "failed";

const descriptions: Record<StartupStage0427, [string, string]> = {
  idle: ["Подготовка не запущена", "Preparation has not started"],
  connecting: ["Проверка соединения с Backend", "Checking backend connection"],
  session: ["Проверка сессии Launcher", "Validating Launcher session"],
  project: ["Выбор проекта", "Selecting project"],
  profile: ["Выбор игрового профиля", "Selecting game profile"],
  manifest: ["Проверка подписанной сборки", "Verifying signed release"],
  java: ["Подготовка проверенной Java", "Preparing verified Java"],
  files: ["Синхронизация файлов Minecraft", "Synchronizing Minecraft files"],
  repair: ["Восстановление повреждённых файлов", "Repairing damaged files"],
  cleanup: ["Удаление неиспользуемых файлов", "Cleaning unused files"],
  ready: ["Проверка завершена: клиент готов", "Checks complete: client ready"],
  launching: ["Запуск Minecraft", "Starting Minecraft"],
  running: ["Minecraft запущен", "Minecraft is running"],
  failed: ["Операция завершилась ошибкой. Проверьте журнал и повторите проверку.", "Operation failed. Review the log and retry checks."],
};

export function startupStatus0427(stage: StartupStage0427, locale: "ru" | "en") {
  return {
    message: descriptions[stage][locale === "ru" ? 0 : 1],
    failed: stage === "failed",
    active: !["idle", "ready", "running", "failed"].includes(stage),
  };
}
