// Чистый планировщик для startup_optimizer_03011; его можно тестировать без React и WebView.
export type IdleScheduler03011 = (work: () => void) => () => void;
export function warmAfterIdle03011<T>(schedule: IdleScheduler03011, warm: (key: T) => Promise<unknown>, keys: readonly T[], canWarm: () => boolean = () => true): () => void {
  let stopped = false;
  const cancel = schedule(() => {
    if (stopped || !canWarm()) return;
    // Ошибка необязательной предварительной загрузки не должна влиять на лаунчер. Последовательная
    // загрузка предотвращает скачки нагрузки CPU и диска при первом отображении после входа.
    void (async () => {
      for (const key of keys) {
        if (stopped || !canWarm()) return;
        try { await warm(key); } catch { /* retry on user navigation */ }
      }
    })();
  });
  return () => { stopped = true; cancel(); };
}
