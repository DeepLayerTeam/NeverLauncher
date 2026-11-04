import React, { useCallback, useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { validProviderPolicy02611, type OfficialProviderPolicy02611 } from './official-provider-model-02611';

type Policy = OfficialProviderPolicy02611;
type Revision = { revision: number; settings: Policy; actor?: string; reason?: string; createdAt?: string };
type Probe = { service: string; reachable: boolean; httpStatus?: number; detail: string };
type Diagnostics = { checkedAt: string; configured: boolean; revision: number; appApprovalStatus: string; checks: Probe[]; note: string };
export function OfficialProviderWorkspace02611({ backendUrl, token }: { backendUrl: string; token: string }) {
  const [current, setCurrent] = useState<Revision | null>(null);
  const [draft, setDraft] = useState<Policy | null>(null);
  const [history, setHistory] = useState<Revision[]>([]);
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const refresh = useCallback(async () => {
    const [config, revisions] = await Promise.all([
      requestJSON<Revision>(backendUrl, '/api/v1/admin/official-provider', token),
      requestJSON<{ items: Revision[] }>(backendUrl, '/api/v1/admin/official-provider/history', token),
    ]);
    setCurrent(config); setDraft({ ...config.settings }); setHistory(revisions.items ?? []);
  }, [backendUrl, token]);
  useEffect(() => { let alive = true; void Promise.all([
    requestJSON<Revision>(backendUrl, '/api/v1/admin/official-provider', token),
    requestJSON<{ items: Revision[] }>(backendUrl, '/api/v1/admin/official-provider/history', token),
  ]).then(([v,h]) => { if (alive) { setCurrent(v); setDraft({...v.settings}); setHistory(h.items??[]); }})
    .catch(e => { if (alive) setError(e.message); }); return () => { alive = false; }; }, [backendUrl, token]);
  function update(p: Partial<Policy>) { setDraft(old => old ? { ...old, ...p } : null); setNotice(''); }
  async function perform(task: () => Promise<void>) { setBusy(true);setError('');setNotice('');try { await task(); }catch(e){ setError(e instanceof Error ? e.message : String(e));}finally{setBusy(false);} }
  const changed = !!current && !!draft && JSON.stringify(current.settings) !== JSON.stringify(draft);
  return <section className="card wide"><div className="registryHeading"><div><h2>Microsoft / Xbox / Minecraft Provider</h2><p className="muted">Настройки собственного public Microsoft-приложения. Только личные Microsoft accounts; секреты и токены здесь не вводятся.</p></div><button disabled={busy} onClick={() => void perform(refresh)}>Обновить</button></div>
    {draft && current ? <>
      <p>Ревизия #{current.revision || 0} · {current.revision === 0 ? 'Используются начальные настройки окружения' : `Изменено: ${current.createdAt || '—'}`}</p>
      <div className="configFields">
        <label className="field">Microsoft Application (Client) ID<input autoComplete="off" spellCheck={false} maxLength={36} value={draft.clientId} onChange={e => update({ clientId: e.target.value.trim() })} /><small className="muted">Собственный зарегистрированный public Client ID в формате UUID.</small></label>
        <label className="field">Issuer <input value="consumers (личные Microsoft accounts)" readOnly /><small className="muted">Другие issuer и произвольные OAuth endpoints запрещены.</small></label>
        <label className="field"><span><input type="checkbox" checked={draft.enabled} onChange={e => update({ enabled:e.target.checked })} /> Разрешить официальную игровую авторизацию</span></label>
        <label className="field"><span><input type="checkbox" checked={draft.browserEnabled} onChange={e => update({ browserEnabled:e.target.checked })} /> System browser + PKCE</span></label>
        <label className="field"><span><input type="checkbox" checked={draft.deviceEnabled} onChange={e => update({ deviceEnabled:e.target.checked })} /> Device Code fallback</span></label>
      </div>
      <label className="field">Причина изменения <input maxLength={500} value={reason} onChange={e => setReason(e.target.value)} /></label>
      <div className="buttonRow"><button disabled={busy || !changed || !draft || !validProviderPolicy02611(draft) || reason.trim().length < 3} onClick={() => void perform(async () => {
        const saved = await requestJSON<Revision>(backendUrl, '/api/v1/admin/official-provider', token, { method:'PUT', body: JSON.stringify({ expectedRevision:current.revision, settings:draft, reason:reason.trim() }) });
        await refresh(); setReason(''); setNotice(`Настройки применены (ревизия #${saved.revision}).`);
      })}>Сохранить с подтверждённой MFA</button><button disabled={busy} onClick={() => void perform(async () => {
        const report = await requestJSON<Diagnostics>(backendUrl,'/api/v1/admin/official-provider/diagnostics',token,{method:'POST'});
        setDiagnostics(report);
      })}>Проверить доступность сервисов</button></div>
      {!validProviderPolicy02611(draft) && <p className="error">Неверный Client ID или недопустимое сочетание политик.</p>}
    </> : <p className="muted">Загрузка конфигурации…</p>}
    {notice && <p className="success" role="status">{notice}</p>}{error && <p className="error" role="alert">{error}</p>}
    {diagnostics && <><h3>Диагностика · {new Date(diagnostics.checkedAt).toLocaleString()}</h3><p>Доступность API не подтверждает одобрение приложения Minecraft Services или владение Java Edition. Внешнее разрешение: <strong>{diagnostics.appApprovalStatus}</strong>.</p>
      <table className="table"><thead><tr><th>Сервис</th><th>Сеть</th><th>HTTP</th></tr></thead><tbody>{diagnostics.checks.map(check => <tr key={check.service}><td>{check.service}</td><td>{check.reachable ? 'Доступен' : 'Не доступен'}</td><td>{check.httpStatus ?? '—'}</td></tr>)}</tbody></table><p className="muted">{diagnostics.note}</p></>}
    <h3>Журнал изменений настроек</h3><div className="tableScroll"><table className="table"><thead><tr><th>Ревизия</th><th>Дата</th><th>Администратор</th><th>Client ID</th><th>Политики</th><th>Причина</th></tr></thead><tbody>{history.map(entry => <tr key={entry.revision}><td>#{entry.revision}</td><td>{entry.createdAt ? new Date(entry.createdAt).toLocaleString() : '—'}</td><td>{entry.actor}</td><td><code>{entry.settings.clientId || '—'}</code></td><td>{entry.settings.enabled ? `Browser: ${entry.settings.browserEnabled ? 'on' : 'off'}, Device: ${entry.settings.deviceEnabled ? 'on' : 'off'}` : 'Отключено'}</td><td>{entry.reason}</td></tr>)}</tbody></table></div>
  </section>;
}
