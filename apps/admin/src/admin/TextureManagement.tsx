import { useCallback, useEffect, useState } from 'react';
import { ApiError, requestJSON } from '../api/client';

type Policy = { projectId: string; revision: number; allowPlayerSkins: boolean; allowPlayerCapes: boolean; defaultSkinModel: 'classic' | 'slim'; defaultSkinDigest: string; defaultCapeDigest: string; fallbackSkinModel: 'classic' | 'slim'; fallbackSkinDigest: string; fallbackCapeDigest: string; maxBytesPerPlayer: number; maxBlobsPerPlayer: number };
type DefaultOption = { digest: string; kind: 'skin' | 'cape'; width: number; height: number; bytes: number };
type Exception = { userId: string; kind: 'skin' | 'cape'; decision: 'allow' | 'deny' | 'inherit'; actorUserId?: string; reason: string; updatedAt?: string };
type PlayerChange = { profileUuid: string; kind: string; revision: number; event: string; actorUserId: string; reason: string; createdAt: string; snapshot: { blobDigest?: string; model?: string; visibility?: string } };
type History = { id: number; revision?: number; userId?: string; kind?: string; from?: string; to?: string; snapshot?: Policy; actorUserId: string; reason: string; createdAt: string };
const blank: Policy = { projectId: '', revision: 0, allowPlayerSkins: true, allowPlayerCapes: false, defaultSkinModel: 'classic', defaultSkinDigest: '', defaultCapeDigest: '', fallbackSkinModel: 'classic', fallbackSkinDigest: '', fallbackCapeDigest: '', maxBytesPerPlayer: 10485760, maxBlobsPerPlayer: 20 };

export function TextureManagement0259({ backendUrl, token, projectId }: { backendUrl: string; token: string; projectId: string }) {
  // Local Yggdrasil and Desktop assignments currently use global projectId=''.
  const [scope, setScope] = useState('');
  const [policy, setPolicy] = useState<Policy>(blank);
  const [options, setOptions] = useState<DefaultOption[]>([]);
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [policyHistory, setPolicyHistory] = useState<History[]>([]);
  const [exceptionHistory, setExceptionHistory] = useState<History[]>([]);
  const [playerHistory, setPlayerHistory] = useState<PlayerChange[]>([]);
  const [reason, setReason] = useState('Обновление политики текстур');
  const [userId, setUserId] = useState('');
  const [kind, setKind] = useState<'skin' | 'cape'>('cape');
  const [decision, setDecision] = useState<'allow' | 'deny' | 'inherit'>('allow');
  const [exceptionReason, setExceptionReason] = useState('Индивидуальное решение администратора');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const qp = `?projectId=${encodeURIComponent(scope)}`;
  const refresh = useCallback(async () => {
    const [p, o, e, h, eh] = await Promise.all([
      requestJSON<Policy>(backendUrl, '/api/v1/admin/textures/policy' + qp, token),
      requestJSON<{ items: DefaultOption[] }>(backendUrl, '/api/v1/admin/textures/default-options' + qp, token),
      requestJSON<{ items: Exception[] }>(backendUrl, '/api/v1/admin/textures/exceptions' + qp, token),
      requestJSON<{ items: History[] }>(backendUrl, '/api/v1/admin/textures/policy/history' + qp, token),
      requestJSON<{ items: History[] }>(backendUrl, '/api/v1/admin/textures/exceptions/history' + qp, token),
    ]);
    setPolicy(p); setOptions(o.items ?? []); setExceptions(e.items ?? []);
    setPolicyHistory(h.items ?? []); setExceptionHistory(eh.items ?? []);
  }, [backendUrl, token, qp]);
  useEffect(() => { let active = true; setPolicy(blank); setError(''); refresh().catch(e => { if (active) setError(String(e)); }); return () => { active = false; }; }, [refresh]);
  const change = <K extends keyof Policy,>(key: K, value: Policy[K]) => setPolicy(p => ({ ...p, [key]: value }));
  async function savePolicy() {
    if (busy) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const next = await requestJSON<Policy>(backendUrl, '/api/v1/admin/textures/policy' + qp, token,
        { method: 'PUT', body: JSON.stringify({ expectedRevision: policy.revision, policy, reason }) });
      setPolicy(next); await refresh(); setMessage('Политика сохранена; настройки применяются сервером при следующем обращении.');
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) await refresh();
      setError(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }
  async function readPlayerHistory() {
    setError(''); setPlayerHistory([]);
    if (!userId.trim()) { setError('Укажите user ID'); return; }
    try {
      const result = await requestJSON<{ items: PlayerChange[] }>(backendUrl, `/api/v1/admin/textures/players/${encodeURIComponent(userId.trim())}/history${qp}`, token);
      setPlayerHistory(result.items ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  }
  async function saveException() {
    if (!userId.trim() || busy) return;
    setBusy(true); setError(''); setMessage('');
    try {
      await requestJSON(backendUrl, `/api/v1/admin/textures/exceptions/${encodeURIComponent(userId.trim())}${qp}`, token,
        { method: 'PUT', body: JSON.stringify({ kind, decision, reason: exceptionReason }) });
      await refresh(); setMessage('Решение пользователя сохранено и зафиксировано в истории.');
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  const preview = (digest: string) => digest && scope === ''
    ? `${backendUrl.replace(/\/$/, '')}/api/v1/textures/blob/${digest}` : '';
  return <section className="card wide" aria-label="Управление текстурами">
    <h2>Управление скинами и плащами</h2>
    <p className="muted">Глобальная политика применяется к локальным Minecraft/Yggdrasil-профилям. Настройки проекта используются только для назначений в этом проекте. Все изменения требуют MFA.</p>
    <label className="field">Область действия
      <select aria-label="Область политики" value={scope} onChange={e => setScope(e.target.value)}>
        <option value="">Глобальная (локальная Minecraft-служба)</option>
        {projectId && <option value={projectId}>Проект: {projectId}</option>}
      </select>
    </label>
    {error && <p className="error" role="alert">{error}</p>}
    {message && <p className="success" role="status">{message}</p>}
    <fieldset disabled={busy}>
      <legend>Политика (ревизия {policy.revision})</legend>
      <label><input type="checkbox" checked={policy.allowPlayerSkins} onChange={e => change('allowPlayerSkins', e.target.checked)} /> Разрешить пользовательские скины</label>
      <label><input type="checkbox" checked={policy.allowPlayerCapes} onChange={e => change('allowPlayerCapes', e.target.checked)} /> Разрешить пользовательские плащи</label>
      <label className="field">Стандартный скин
        <select value={policy.defaultSkinDigest} onChange={e => change('defaultSkinDigest', e.target.value)}>
          <option value="">Без стандартной текстуры</option>
          {options.filter(o => o.kind === 'skin').map(o => <option value={o.digest} key={o.digest}>{o.digest.slice(0, 18)}… ({o.width}×{o.height})</option>)}
          {policy.defaultSkinDigest && !options.some(o => o.digest === policy.defaultSkinDigest) && <option value={policy.defaultSkinDigest}>Текущий: {policy.defaultSkinDigest.slice(0, 18)}…</option>}
        </select>
      </label>
      <label className="field">Модель стандартного скина
        <select value={policy.defaultSkinModel} onChange={e => change('defaultSkinModel', e.target.value as 'classic' | 'slim')}><option value="classic">Classic (Steve)</option><option value="slim">Slim (Alex)</option></select>
      </label>
      <label className="field">Стандартный плащ
        <select value={policy.defaultCapeDigest} onChange={e => change('defaultCapeDigest', e.target.value)}>
          <option value="">Без стандартного плаща</option>
          {options.filter(o => o.kind === 'cape').map(o => <option value={o.digest} key={o.digest}>{o.digest.slice(0, 18)}… ({o.width}×{o.height})</option>)}
          {policy.defaultCapeDigest && !options.some(o => o.digest === policy.defaultCapeDigest) && <option value={policy.defaultCapeDigest}>Текущий: {policy.defaultCapeDigest.slice(0, 18)}…</option>}
        </select>
      </label>
      <label className="field">Резервный скин (если выбранный скин недоступен)
        <select value={policy.fallbackSkinDigest} onChange={e => change('fallbackSkinDigest', e.target.value)}>
          <option value="">Без резервного скина</option>
          {options.filter(o => o.kind === 'skin').map(o => <option value={o.digest} key={o.digest}>{o.digest.slice(0, 18)}… ({o.width}×{o.height})</option>)}
          {policy.fallbackSkinDigest && !options.some(o => o.digest === policy.fallbackSkinDigest) && <option value={policy.fallbackSkinDigest}>Текущий: {policy.fallbackSkinDigest.slice(0, 18)}…</option>}
        </select>
      </label>
      <label className="field">Модель резервного скина<select value={policy.fallbackSkinModel} onChange={e => change('fallbackSkinModel', e.target.value as 'classic' | 'slim')}><option value="classic">Classic</option><option value="slim">Slim</option></select></label>
      <label className="field">Резервный плащ
        <select value={policy.fallbackCapeDigest} onChange={e => change('fallbackCapeDigest', e.target.value)}>
          <option value="">Без резервного плаща</option>
          {options.filter(o => o.kind === 'cape').map(o => <option value={o.digest} key={o.digest}>{o.digest.slice(0, 18)}… ({o.width}×{o.height})</option>)}
          {policy.fallbackCapeDigest && !options.some(o => o.digest === policy.fallbackCapeDigest) && <option value={policy.fallbackCapeDigest}>Текущий: {policy.fallbackCapeDigest.slice(0, 18)}…</option>}
        </select>
      </label>
      <div className="textureAdminPreviews">
        {(['defaultSkinDigest','defaultCapeDigest','fallbackSkinDigest','fallbackCapeDigest'] as const).map(k => preview(policy[k]) && <div key={k}><img alt={k === 'defaultSkinDigest' ? 'Стандартный скин PNG' : 'Стандартный плащ PNG'} src={preview(policy[k])} width={100} height={100} style={{ imageRendering: 'pixelated', objectFit: 'contain' }} /></div>)}
      </div>
      <label className="field">Максимум байт на игрока<input type="number" min={1024} max={1073741824} value={policy.maxBytesPerPlayer} onChange={e => change('maxBytesPerPlayer', Number(e.target.value))}/></label>
      <label className="field">Максимум файлов на игрока<input type="number" min={1} max={10000} value={policy.maxBlobsPerPlayer} onChange={e => change('maxBlobsPerPlayer', Number(e.target.value))}/></label>
      <label className="field">Причина изменения<input value={reason} maxLength={500} minLength={3} onChange={e => setReason(e.target.value)}/></label>
      <button onClick={savePolicy} disabled={busy || reason.trim().length < 3}>Сохранить политику (MFA)</button>
      <button onClick={() => refresh().catch(e => setError(String(e)))} disabled={busy}>Перезагрузить</button>
    </fieldset>
    <fieldset disabled={busy}>
      <legend>Индивидуальные исключения</legend>
      <label className="field">User ID (не Minecraft UUID)<input value={userId} onChange={e => setUserId(e.target.value)} placeholder="ID пользователя" /></label>
      <label className="field">Тип<select value={kind} onChange={e => setKind(e.target.value as 'skin'|'cape')}><option value="skin">Скин</option><option value="cape">Плащ</option></select></label>
      <label className="field">Решение<select value={decision} onChange={e => setDecision(e.target.value as typeof decision)}><option value="allow">Разрешить</option><option value="deny">Запретить</option><option value="inherit">Наследовать политику</option></select></label>
      <label className="field">Причина<input value={exceptionReason} maxLength={500} onChange={e => setExceptionReason(e.target.value)}/></label>
      <button disabled={!userId.trim() || busy || exceptionReason.trim().length < 3} onClick={saveException}>Применить исключение (MFA)</button>
      <button disabled={!userId.trim() || busy} onClick={readPlayerHistory}>История скинов и плащей пользователя</button>
      {playerHistory.length > 0 && <table><thead><tr><th>Профиль</th><th>Тип</th><th>Действие</th><th>Ревизия</th><th>Дата</th></tr></thead><tbody>
        {playerHistory.map((h,i) => <tr key={`${h.profileUuid}:${h.kind}:${h.revision}:${i}`}><td>{h.profileUuid}</td><td>{h.kind}</td><td>{h.event}</td><td>{h.revision}</td><td>{h.createdAt}</td></tr>)}
      </tbody></table>}
      <table><thead><tr><th>Пользователь</th><th>Тип</th><th>Решение</th><th>Изменено</th></tr></thead><tbody>
        {exceptions.map(item => <tr key={item.userId + item.kind}><td><button onClick={() => { setUserId(item.userId); setKind(item.kind); setDecision(item.decision); setExceptionReason(item.reason); }}>{item.userId}</button></td><td>{item.kind}</td><td>{item.decision}</td><td>{item.updatedAt || '—'}</td></tr>)}
      </tbody></table>
    </fieldset>
    <details><summary>История политик ({policyHistory.length})</summary><table><thead><tr><th>Ревизия</th><th>Администратор</th><th>Причина</th><th>Дата</th></tr></thead><tbody>{policyHistory.map(h => <tr key={h.id}><td>{h.revision}</td><td>{h.actorUserId}</td><td>{h.reason}</td><td>{h.createdAt}</td></tr>)}</tbody></table></details>
    <details><summary>История исключений ({exceptionHistory.length})</summary><table><thead><tr><th>Пользователь</th><th>Тип</th><th>Изменение</th><th>Администратор / причина</th></tr></thead><tbody>{exceptionHistory.map(h => <tr key={h.id}><td>{h.userId}</td><td>{h.kind}</td><td>{h.from} → {h.to}</td><td>{h.actorUserId}: {h.reason}</td></tr>)}</tbody></table></details>
  </section>;
}
