export type UpdatePreferences = { autoCheck: boolean; autoDownload: boolean; intervalHours: 6 | 24 | 168 };
export const UPDATE_PREFERENCES_KEY = 'launcher.native-updates.v1';
export const DEFAULT_UPDATE_PREFERENCES: UpdatePreferences = { autoCheck: true, autoDownload: false, intervalHours: 24 };
export type Offer = { currentVersion: string; status: 'disabled' | 'current' | 'available'; version: string | null; notes: string | null };
export type Progress = { stage: 'download' | 'verify'; downloaded: number; total: number | null };
export type Phase = 'idle' | 'checking' | 'available' | 'downloading' | 'verifying' | 'ready' | 'installing' | 'scheduled' | 'retry' | 'rejected' | 'error' | 'current' | 'disabled';
export function readUpdatePreferences(raw: string | null): UpdatePreferences {
  try {
    const value = JSON.parse(raw ?? 'null');
    if (!value || typeof value !== 'object') return { ...DEFAULT_UPDATE_PREFERENCES };
    const autoCheck = typeof value.autoCheck === 'boolean' ? value.autoCheck : true;
    return { autoCheck, autoDownload: autoCheck && value.autoDownload === true,
      intervalHours: [6, 24, 168].includes(value.intervalHours) ? value.intervalHours : 24 };
  } catch { return { ...DEFAULT_UPDATE_PREFERENCES }; }
}
export function isUpdateBusy(phase: Phase): boolean {
  return ['checking', 'downloading', 'verifying', 'installing', 'scheduled'].includes(phase);
}
export function automaticCheckDue(prefs: UpdatePreferences, phase: Phase, lastAttempt: number | null, now: number): boolean {
  if (!prefs.autoCheck || isUpdateBusy(phase) || phase === 'ready' || phase === 'disabled') return false;
  return lastAttempt === null || now < lastAttempt || now - lastAttempt >= ((phase === 'error' || phase === 'retry') ? 15 * 60_000 : prefs.intervalHours * 3_600_000);
}
export function progressPercent(progress: Progress): number | null {
  if (!Number.isFinite(progress.downloaded) || progress.downloaded < 0 || !progress.total || !Number.isFinite(progress.total) || progress.total < 0) return null;
  return Math.min(100, Math.floor(progress.downloaded / progress.total * 100));
}

export const UPDATE_ATTEMPT_KEY = 'launcher.native-updates.attempt.v1';
export function updateFailure(error: unknown): { phase: Phase; message: string } {
  const raw = String(error);
  if (raw.startsWith('retry: ')) return { phase: 'retry', message: raw.slice(7) };
  if (raw.startsWith('rejected: ')) return { phase: 'rejected', message: raw.slice(10) };
  if (raw.startsWith('expired: ')) return { phase: 'error', message: raw.slice(9) };
  return { phase: 'error', message: raw };
}
export function previousInstallFailed(attempt: string | null, result: Offer): boolean {
  return Boolean(attempt && result.status === 'available' && attempt === result.version && result.currentVersion !== attempt);
}
