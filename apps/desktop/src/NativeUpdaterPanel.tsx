import { useCallback, useEffect, useRef, useState } from "react";
import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import { automaticCheckDue, DEFAULT_UPDATE_PREFERENCES, isUpdateBusy, progressPercent, readUpdatePreferences, UPDATE_PREFERENCES_KEY, UPDATE_ATTEMPT_KEY, updateFailure, previousInstallFailed, type Offer, type Phase, type Progress, type UpdatePreferences, type UpdateTrack } from "./native_update_experience";

function initialPreferences(): UpdatePreferences {
  try { return readUpdatePreferences(localStorage.getItem(UPDATE_PREFERENCES_KEY)); }
  catch { return { ...DEFAULT_UPDATE_PREFERENCES }; }
}

// Mounted once by App, independently of the current navigation screen.
export default function NativeUpdaterPanel({ settingsVisible, enabled }: { settingsVisible: boolean; enabled: boolean }) {
  const [preferences, setPreferences] = useState(initialPreferences);
  const prefs = useRef(preferences);
  const [storageError, setStorageError] = useState(false);
  const [offer, setOffer] = useState<Offer | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [phase, setPhase] = useState<Phase>('idle');
  const phaseRef = useRef<Phase>('idle');
  const [message, setMessage] = useState("");
  const [lastChecked, setLastChecked] = useState<number | null>(null);
  const lastAttempt = useRef<number | null>(null);
  const lock = useRef(false);
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const transition = useCallback((next: Phase, text: string) => {
    phaseRef.current = next;
    if (mounted.current) { setPhase(next); setMessage(text); }
  }, []);
  function savePreferences(next: UpdatePreferences) {
    prefs.current = next; setPreferences(next);
    try { localStorage.setItem(UPDATE_PREFERENCES_KEY, JSON.stringify(next)); setStorageError(false); }
    catch { setStorageError(true); }
  }
  // Called under the operation lock; no installation is ever triggered automatically.
  const download = useCallback(async (version: string, track: UpdateTrack) => {
    setProgress(null); transition('downloading', 'Скачиваем обновление…');
    const channel = new Channel<Progress>();
    channel.onmessage = (event) => {
      if (!mounted.current) return;
      setProgress(event);
      if (event.stage === 'verify') transition('verifying', 'Проверяем подпись, версию и платформу…');
    };
    try {
      await invoke('native_update_download', { version, channel: track, progress: channel });
      transition('ready', 'Пакет скачан и проверен. Установите его, когда будете готовы.');
    } finally { channel.onmessage = () => {}; }
  }, [transition]);
  const check = useCallback(async (automatic = false) => {
    if (!enabled || !isTauri() || lock.current || phaseRef.current === 'scheduled') return;
    lock.current = true; lastAttempt.current = Date.now();
    setOffer(null); setProgress(null); transition('checking', 'Проверяем обновления…');
    try {
      const track = prefs.current.channel;
      const result = await invoke<Offer>('native_update_check', { channel: track });
      if (!mounted.current) return;
      setOffer(result); setLastChecked(Date.now());
      if (result.status === 'available' && result.version) {
        let failed = false;
        try {
          const attempt = localStorage.getItem(UPDATE_ATTEMPT_KEY);
          failed = previousInstallFailed(attempt, result);
          if (attempt && !failed) localStorage.removeItem(UPDATE_ATTEMPT_KEY);
        } catch { /* preference storage is not a trust boundary */ }
        transition('available', failed ? 'Предыдущая установка не подтверждена: используется прежняя версия. Проверьте журнал update.log в updater-helpers; повторите загрузку вручную.' : 'Доступна новая версия. Подпись будет проверена после скачивания.');
        if (!failed && automatic && prefs.current.autoCheck && prefs.current.autoDownload) await download(result.version, track);
      } else if (result.status === 'disabled') transition('disabled', 'В этой сборке не настроен доверенный источник обновлений.');
      else { try { if (localStorage.getItem(UPDATE_ATTEMPT_KEY) === result.currentVersion) localStorage.removeItem(UPDATE_ATTEMPT_KEY); } catch {} transition('current', 'В выбранном канале нет более новой версии. Автоматическое понижение версии запрещено.'); }
    } catch (error) { lastAttempt.current = Date.now(); const failure = updateFailure(error); transition(failure.phase, failure.message); }
    finally { lock.current = false; }
  }, [download, enabled, transition]);
  useEffect(() => {
    if (!enabled || !preferences.autoCheck || !isTauri()) return;
    const tick = () => {
      if (automaticCheckDue(prefs.current, phaseRef.current, lastAttempt.current, Date.now())) void check(true);
    };
    const startup = window.setTimeout(tick, 5000);
    const timer = window.setInterval(tick, 60_000);
    window.addEventListener('online', tick);
    window.addEventListener('focus', tick);
    return () => { window.clearTimeout(startup); window.clearInterval(timer); window.removeEventListener('online', tick); window.removeEventListener('focus', tick); };
  }, [enabled, preferences.autoCheck, preferences.intervalHours, check]);
  function changeChannel(track: UpdateTrack) {
    if (lock.current || isUpdateBusy(phaseRef.current) || track === prefs.current.channel) return;
    if (track === 'beta' && !window.confirm('Beta может содержать ошибки. Перейти в тестовый канал?')) return;
    savePreferences({ ...prefs.current, channel: track });
    setOffer(null); setProgress(null); setLastChecked(null); lastAttempt.current = null;
    transition('idle', 'Канал изменён. Предыдущий пакет больше не используется.');
    // This explicit user action checks the newly selected channel even when automatic checks are off.
    void check(false);
  }
  async function downloadSelected() {
    if (!enabled || lock.current || !['available', 'retry'].includes(phaseRef.current) || !offer?.version) return;
    lock.current = true;
    try { await download(offer.version, prefs.current.channel); }
    catch (error) { lastAttempt.current = Date.now(); const failure = updateFailure(error); transition(failure.phase, failure.message); }
    finally { lock.current = false; }
  }
  async function install() {
    if (!enabled || lock.current || phaseRef.current !== 'ready' || !offer?.version) return;
    lock.current = true;
    try { localStorage.setItem(UPDATE_ATTEMPT_KEY, offer.version); } catch {}
    transition('installing', 'Передаём проверенный пакет установщику…');
    try {
      await invoke('native_update_install', { version: offer.version, channel: prefs.current.channel });
      transition('scheduled', 'Установка запланирована. Launcher будет закрыт и перезапущен установщиком.');
    } catch (error) {
      const ready = await invoke<boolean>('native_update_ready', { version: offer.version, channel: prefs.current.channel }).catch(() => false);
      lastAttempt.current = Date.now();
      try { localStorage.removeItem(UPDATE_ATTEMPT_KEY); } catch {}
      const failure = updateFailure(error);
      transition(ready ? 'ready' : failure.phase, failure.message + (ready ? ' Пакет сохранён, повторите установку.' : ' Повторите проверку обновлений.'));
    } finally { lock.current = false; }
  }
  const busy = isUpdateBusy(phase);
  const visible = settingsVisible || ['available', 'downloading', 'verifying', 'ready', 'installing', 'scheduled', 'retry', 'rejected', 'error'].includes(phase);
  if (!visible) return null;
  const percent = progress ? progressPercent(progress) : null;
  return <section className="panel nativeUpdatePanel" aria-label="Обновления Launcher">
    <h3>Обновление Launcher</h3>
    {offer && <p>Текущая версия: {offer.currentVersion}{offer.version && ` · Новая версия: ${offer.version} (${offer.channel === 'beta' ? 'Beta' : 'Stable'})`}</p>}
    {settingsVisible && <div className="nativeUpdatePreferences">
      <label>Канал обновлений <select disabled={busy || !enabled || !isTauri()} value={preferences.channel} onChange={e => changeChannel(e.target.value as UpdateTrack)}>
        <option value="stable">Stable — стабильные выпуски</option><option value="beta">Beta — тестовые и стабильные выпуски</option>
      </select></label>
      <p>Beta включается добровольно. Возврат в Stable не понижает установленную версию; потребуется дождаться более нового стабильного выпуска.</p>
      <label><input type="checkbox" checked={preferences.autoCheck} onChange={e => savePreferences({ ...preferences, autoCheck: e.target.checked, autoDownload: e.target.checked && preferences.autoDownload })}/> Проверять обновления автоматически</label>
      <label>Период проверки <select disabled={!preferences.autoCheck} value={preferences.intervalHours} onChange={e => savePreferences({ ...preferences, intervalHours: Number(e.target.value) as UpdatePreferences['intervalHours'] })}>
        <option value={6}>Каждые 6 часов</option><option value={24}>Каждые 24 часа</option><option value={168}>Раз в неделю</option>
      </select></label>
      <label><input type="checkbox" disabled={!preferences.autoCheck} checked={preferences.autoDownload} onChange={e => savePreferences({ ...preferences, autoDownload: e.target.checked })}/> Автоматически скачивать и проверять пакеты (без установки)</label>
      {storageError && <p role="alert">Не удалось сохранить настройки обновлений. Они действуют до закрытия приложения.</p>}
      <p>Последняя успешная проверка: {lastChecked ? new Date(lastChecked).toLocaleString() : 'ещё не выполнялась'}</p>
    </div>}
    {!isTauri() && <p>Обновление доступно только в нативном приложении.</p>}
    <div className="actions">
      <button type="button" disabled={busy || !enabled || !isTauri()} onClick={() => void check()}>{phase === 'ready' ? 'Проверить заново (сбросить скачанный пакет)' : 'Проверить обновления'}</button>
      {(phase === 'available' || phase === 'retry') && offer?.version && <button type="button" disabled={!enabled} onClick={() => void downloadSelected()}>{phase === 'retry' ? 'Повторить скачивание' : 'Скачать'} {offer?.version}</button>}
      {phase === 'ready' && <button type="button" className="primary" disabled={!enabled} onClick={() => void install()}>Установить {offer?.version} и перезапустить</button>}
    </div>
    <p role="status" aria-live="polite">{message}</p>
    {(phase === 'downloading' || phase === 'verifying') && <div>
      <progress aria-label="Скачивание обновления" max={100} value={percent ?? undefined}/>
      {progress && <span> {(progress.downloaded / 1048576).toFixed(1)} МиБ{progress.total ? ` / ${(progress.total / 1048576).toFixed(1)} МиБ` : ''}{percent !== null ? ` · ${percent}%` : ''}</span>}
    </div>}
    {offer?.status === 'available' && <details open={settingsVisible || undefined}>
      <summary>Что нового в {offer.version}</summary>
      <div className="nativeUpdateNotes">{offer.notes || 'Описание изменений не опубликовано.'}</div>
      <small>Описание из ленты обновлений, не является криптографически проверенной частью пакета.</small>
    </details>}
    <p>Перед установкой закройте Minecraft и завершите другие операции Launcher. Неполная загрузка сохраняется в памяти до повторной попытки или закрытия приложения; при отсутствии безопасного HTTP-валидатора загрузка начнётся заново. Проверенный пакет хранится до установки, новой проверки или закрытия приложения.</p>
  </section>;
}
