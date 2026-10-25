// Pure scheduler used by startup_optimizer_03011; testable without React/WebView.
export type IdleScheduler03011 = (work: () => void) => () => void;
export function warmAfterIdle03011<T>(schedule: IdleScheduler03011, warm: (key: T) => Promise<unknown>, keys: readonly T[]): () => void {
  let stopped = false;
  const cancel = schedule(() => {
    if (stopped) return;
    // Never let an optional preload failure affect the launcher; serial
    // loading avoids CPU/disk bursts during the first authenticated paint.
    void (async () => {
      for (const key of keys) {
        if (stopped) return;
        try { await warm(key); } catch { /* retry on user navigation */ }
      }
    })();
  });
  return () => { stopped = true; cancel(); };
}
