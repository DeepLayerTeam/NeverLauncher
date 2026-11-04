// Player-facing adaptation of native Runtime download events.
// Never interpret wire bytes as verified files or "staged" as a committed release.
export type NativeTransfer0354 = {
  operationId: string;
  phase: string;
  totalFiles: number;
  queued: number;
  active: number;
  completed: number;
  failed: number;
  skipped: number;
  bytesExpected: number;
  bytesTransferred: number;
  bytesVerified?: number;
  speedBytesPerSecond?: number;
  etaSeconds?: number | null;
  elapsedSeconds?: number;
  cacheHits: number;
  bytesReused: number;
  currentFile?: string | null;
};

export type Recovery0354 = {
  title: string;
  explanation: string;
  instruction: string;
  action: "retry" | "repair" | "none";
};
const numeric = (v: unknown): number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
export function bytes0354(value: number): string {
  const v = numeric(value);
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
  let index = 0,
    size = v;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index++;
  }
  return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
}
export function duration0354(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0)
    return "рассчитывается";
  const seconds = Math.ceil(value);
  if (seconds >= 86400)
    return `${Math.floor(seconds / 86400)} д ${Math.floor((seconds % 86400) / 3600)} ч`;
  if (seconds >= 3600)
    return `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)} мин ${seconds % 60} с`;
  return `${seconds} с`;
}
const phases: Record<string, string> = {
  starting: "Подготовка файлов",
  downloading: "Загрузка файлов",
  retrying: "Повтор соединения",
  "mirror-fallback": "Переключение на зеркало",
  "cache-hit": "Восстановление из проверенного кеша",
  "cache-write-failed": "Кеш недоступен (установка продолжается)",
  verified: "Контрольная сумма подтверждена",
  staged: "Файлы загружены; публикация ещё не завершена",
  verifying: "Финальная проверка SHA-256",
  publishing: "Атомарная установка файлов",
  completed: "Установка подтверждена",
  paused: "Приостановлено",
  cancelled: "Отменено",
  failed: "Загрузка завершилась с ошибками",
  "failed-file": "Ошибка загрузки файла",
};
export function progress0354(progress: NativeTransfer0354 | null) {
  if (!progress) return null;
  const expected = numeric(progress.bytesExpected),
    verified = numeric(progress.bytesVerified);
  const finished = progress.phase === "completed";
  // Percentage means verified bytes, not HTTP bytes (which include retries).
  const percent =
    expected > 0
      ? Math.min(
          100,
          Math.floor((100 * Math.min(expected, verified)) / expected),
        )
      : finished
        ? 100
        : 0;
  return {
    label: phases[progress.phase] || "Операция установки",
    percent: finished ? 100 : percent,
    verified: bytes0354(verified),
    expected: bytes0354(expected),
    received: bytes0354(progress.bytesTransferred),
    speed:
      numeric(progress.speedBytesPerSecond) > 0
        ? `${bytes0354(progress.speedBytesPerSecond!)} /с`
        : "—",
    eta: ["downloading", "retrying", "starting"].includes(progress.phase)
      ? duration0354(progress.etaSeconds)
      : "—",
    completed: finished,
    canInterrupt: !["publishing", "completed", "cancelled"].includes(
      progress.phase,
    ),
  };
}

export function recovery0354(error: unknown): Recovery0354 {
  const raw = String(error instanceof Error ? error.message : error || "");
  const value = raw.toLowerCase();
  if (
    /signature|ed25519|pinned|public key|trust|signed|подпис|ключ/.test(value)
  )
    return {
      title: "Невозможно подтвердить подлинность сборки",
      explanation:
        "Подпись или закреплённый ключ не прошли проверку. Установка заблокирована.",
      instruction: "Получите новый подписанный bundle от владельца проекта.",
      action: "none",
    };
  if (
    /no space|not enough space|disk full|insufficient space|free space|места на диске|свободного места/.test(
      value,
    )
  )
    return {
      title: "Недостаточно места на диске",
      explanation:
        "Для загрузки и транзакционной установки нужно свободное место.",
      instruction: "Освободите место на диске игры и нажмите «Повторить».",
      action: "retry",
    };
  if (
    /permission|access denied|read-only|operation not permitted|отказано в доступе/.test(
      value,
    )
  )
    return {
      title: "Нет доступа к игровому каталогу",
      explanation: "Операционная система запретила запись или чтение файлов.",
      instruction: "Проверьте права на каталог и повторите операцию.",
      action: "retry",
    };
  if (
    /untracked user file|user-owned|player-owned|conflict with|conflicts with/.test(
      value,
    )
  )
    return {
      title: "Конфликт с пользовательским файлом",
      explanation: "Установка не перезаписывает посторонние данные игрока.",
      instruction:
        "Сохраните конфликтующий файл отдельно и запустите восстановление.",
      action: "repair",
    };
  if (
    /sha.?256|digest|checksum|corrupt|mismatch|integrity|поврежд|контрольн/.test(
      value,
    )
  )
    return {
      title: "Повреждение или несовпадение файлов",
      explanation: "Хеши файлов отличаются от подписанной сборки.",
      instruction: "Запустите «Восстановить повреждённое».",
      action: "repair",
    };
  if (
    /timeout|timed out|connection|network|dns|http (?:4(?:08|29)|5\d\d)|retry|mirror|source|сервер недоступен|соединен/.test(
      value,
    )
  )
    return {
      title: "Не удалось получить файлы",
      explanation: "Сервер загрузки или сеть не ответили корректно.",
      instruction: "Проверьте соединение и нажмите «Повторить».",
      action: "retry",
    };
  return {
    title: "Установка не завершена",
    explanation: "Runtime не подтвердил успешное завершение операции.",
    instruction:
      "Запустите «Восстановить повреждённое»; при повторной ошибке экспортируйте диагностику.",
    action: "repair",
  };
}
