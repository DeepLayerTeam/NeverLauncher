import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, requestJSON } from '../api/client';
import { recoveryAdvice } from './lifecycle';

export interface OperationalSettings {
  auditDefaultPageSize: number; auditMaxPageSize: number; auditLookbackDays: number;
  auditExposeClientDetails: boolean; jobsDefaultPageSize: number; jobsMaxPageSize: number;
}
interface Revision { revision: number; settings: OperationalSettings; actor: string; reason: string; restoredFrom?: number; createdAt: string }
interface Diff { field: keyof OperationalSettings; before: number | boolean; after: number | boolean; restartRequired: boolean }
interface Preview { valid: boolean; revision: number; diff: Diff[]; restartRequired: boolean }
const fields: Array<{ key: keyof OperationalSettings; title: string; help: string; min?: number; max?: number }> = [
  { key: 'auditDefaultPageSize', title: 'Аудит: строк на странице', help: 'Размер серверной страницы по умолчанию', min: 5, max: 100 },
  { key: 'auditMaxPageSize', title: 'Аудит: максимальный размер страницы', help: 'Ограничивает количество записей, выдаваемых API', min: 5, max: 200 },
  { key: 'auditLookbackDays', title: 'Аудит: период по умолчанию (дней)', help: 'Поиск без даты начала охватывает заданный период; явный диапазон не ограничен', min: 1, max: 3650 },
  { key: 'auditExposeClientDetails', title: 'Отображать IP и User-Agent в аудите', help: 'При отключении API скрывает IP и User-Agent в результатах поиска' },
  { key: 'jobsDefaultPageSize', title: 'Jobs: строк на странице', help: 'Размер страницы по умолчанию', min: 5, max: 100 },
  { key: 'jobsMaxPageSize', title: 'Jobs: максимальный размер страницы', help: 'Серверный предел выдачи jobs', min: 5, max: 200 },
];
export function configDiff(a: OperationalSettings, b: OperationalSettings): Diff[] {
  return fields.filter(f => a[f.key] !== b[f.key]).map(f => ({ field: f.key, before: a[f.key], after: b[f.key], restartRequired: false }));
}
export function ConfigWorkspace({ backendUrl, token }: { backendUrl: string; token: string }) {
  const [current, setCurrent] = useState<Revision | null>(null);
  const [draft, setDraft] = useState<OperationalSettings | null>(null);
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [reason, setReason] = useState('Обновление операционных настроек Admin');
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [restore, setRestore] = useState<number | null>(null);
  const [confirmed, setConfirmed] = useState('');
  const localDiff = useMemo(() => current && draft ? configDiff(current.settings, draft) : [], [current, draft]);
  const refresh = useCallback(async () => {
    const [now, history] = await Promise.all([
      requestJSON<Revision>(backendUrl, '/api/v1/admin/config', token),
      requestJSON<{ items: Revision[] }>(backendUrl, '/api/v1/admin/config/revisions', token),
    ]);
    setCurrent(now); setDraft({ ...now.settings }); setRevisions(history.items ?? []);
    setPreview(null); setRestore(null); setConfirmed(''); setError('');
  }, [backendUrl, token]);
  useEffect(() => { let active = true; void Promise.all([
    requestJSON<Revision>(backendUrl, '/api/v1/admin/config', token),
    requestJSON<{ items: Revision[] }>(backendUrl, '/api/v1/admin/config/revisions', token),
  ]).then(([now, history]) => { if (active) { setCurrent(now); setDraft({ ...now.settings }); setRevisions(history.items ?? []); } })
    .catch(e => { if (active) setError(e.message); }); return () => { active = false; }; }, [backendUrl, token]);
  function change<K extends keyof OperationalSettings>(key: K, value: OperationalSettings[K]) {
    setDraft(old => old ? { ...old, [key]: value } : old); setPreview(null); setRestore(null); setConfirmed('');
  }
  function explain(e: unknown) {
    const err = e as ApiError;
    const advice = err.reasonCode === 'revision_conflict' ? 'Настройки изменены в другой вкладке или другим администратором. Обновите страницу и повторите проверку.' : recoveryAdvice(err.message);
    setError(`${err.message}. ${advice}`);
  }
  async function run<T>(fn: () => Promise<T>, after: (result: T) => Promise<void> | void) {
    setBusy(true); setError(''); setNotice('');
    try { await after(await fn()); } catch (e) { explain(e); } finally { setBusy(false); }
  }
  if (!current || !draft) return <section className="card wide"><h2>Операционные настройки</h2>{error ? <p className="error">{error}</p> : <p>Загрузка актуальной ревизии…</p>}<button onClick={() => void refresh().catch(explain)}>Повторить</button></section>;
  const validInput = reason.trim().length >= 3 && draft.auditDefaultPageSize >= 5 && draft.auditMaxPageSize >= draft.auditDefaultPageSize && draft.jobsDefaultPageSize >= 5 && draft.jobsMaxPageSize >= draft.jobsDefaultPageSize;
  const payload = { expectedRevision: current.revision, settings: draft, reason: reason.trim() };
  return <section className="card wide"><div className="registryHeading"><div><h2>Операционные настройки</h2><p className="muted">Только безопасные параметры Admin/API. Секреты, сеть, ключи подписи и БД изменяются в конфигурации развертывания.</p></div><button disabled={busy} onClick={() => void refresh().catch(explain)}>Обновить ревизию</button></div>
    <p>Действующая ревизия: <strong>#{current.revision}</strong> · {current.createdAt || 'первоначальные значения'} · рестарт не требуется</p>
    <div className="configFields">{fields.map(f => <label className="field" key={f.key}><span>{f.title}</span>{typeof draft[f.key] === 'boolean' ? <input type="checkbox" checked={Boolean(draft[f.key])} onChange={e => change(f.key, e.target.checked as never)} /> : <input type="number" min={f.min} max={f.max} step="1" value={Number(draft[f.key])} onChange={e => change(f.key, Number(e.target.value) as never)} />}<small className="muted">{f.help}</small></label>)}</div>
    <label className="field">Причина изменения<input value={reason} maxLength={500} onChange={e => { setReason(e.target.value); setPreview(null); }} /></label>
    <h3>Изменения ({localDiff.length})</h3>{localDiff.length ? <table className="table"><thead><tr><th>Поле</th><th>Было</th><th>Станет</th><th>Рестарт</th></tr></thead><tbody>{localDiff.map(d => <tr key={d.field}><td>{d.field}</td><td>{String(d.before)}</td><td>{String(d.after)}</td><td>Не нужен</td></tr>)}</tbody></table> : <p className="muted">Настройки не изменены.</p>}
    <div className="buttonRow"><button disabled={busy || !validInput || localDiff.length === 0} onClick={() => void run(() => requestJSON<Preview>(backendUrl, '/api/v1/admin/config/validate', token, { method: 'POST', body: JSON.stringify(payload) }), result => { setPreview(result); setNotice('Проверка пройдена; можно применить ревизию.'); })}>Проверить на Backend</button><button disabled={busy || !preview?.valid || preview.revision !== current.revision || preview.diff.length === 0 || !preview.diff.every(d => localDiff.some(v => v.field === d.field && v.before === d.before && v.after === d.after))} onClick={() => void run(() => requestJSON<{ revision: Revision; diff: Diff[] }>(backendUrl, '/api/v1/admin/config', token, { method: 'PUT', body: JSON.stringify(payload) }), async result => { setNotice(`Применена ревизия #${result.revision.revision}.`); await refresh(); setNotice(`Применена ревизия #${result.revision.revision}.`); })}>Применить с MFA</button></div>
    {preview && <p className="success">Проверено на Backend: {preview.diff.length} изменений; рестарт {preview.restartRequired ? 'необходим' : 'не требуется'}.</p>}
    <h3>История и восстановление</h3><div className="tableScroll"><table className="table"><thead><tr><th>Ревизия</th><th>Дата</th><th>Автор</th><th>Причина</th><th>Действия</th></tr></thead><tbody>{revisions.map(rev => <tr key={rev.revision}><td>#{rev.revision}</td><td>{rev.createdAt || '—'}</td><td>{rev.actor}</td><td>{rev.reason}{rev.restoredFrom ? ` (из #${rev.restoredFrom})` : ''}</td><td><button disabled={busy || rev.revision === current.revision} onClick={() => { setRestore(rev.revision); setDraft({ ...rev.settings }); setPreview(null); setConfirmed(''); setReason(`Восстановление ревизии ${rev.revision}`); }}>Выбрать для отката</button></td></tr>)}</tbody></table></div>
    {restore !== null && <div className="configRestore"><h3>Восстановление ревизии #{restore}</h3><p>Предыдущая конфигурация будет восстановлена как новая ревизия #{current.revision + 1}. Это не затрагивает историю и не требует рестарта.</p><label className="field">Введите <code>RESTORE #{restore}</code> для подтверждения (после проверки на Backend)<input value={confirmed} onChange={e => setConfirmed(e.target.value)} /></label><button disabled={busy || confirmed !== `RESTORE #${restore}` || !preview?.valid || preview.revision !== current.revision || !preview.diff.every(d => localDiff.some(v => v.field === d.field && v.before === d.before && v.after === d.after))} onClick={() => void run(() => requestJSON<{ revision: Revision }>(backendUrl, '/api/v1/admin/config/restore', token, { method: 'POST', body: JSON.stringify({ expectedRevision: current.revision, restoreRevision: restore, reason: reason.trim() }) }), async result => { await refresh(); setNotice(`Восстановлено как ревизия #${result.revision.revision}.`); })}>Восстановить с MFA</button></div>}
    {notice && <p className="success">{notice}</p>}{error && <p className="error" role="alert">{error}</p>}
    <a href="#/audit?query=config%3Achanged">Открыть аудит изменений конфигурации</a>
  </section>;
}
