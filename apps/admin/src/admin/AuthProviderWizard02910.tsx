import React, { useCallback, useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type ProviderKind = 'sql' | 'http' | 'oidc' | 'microsoft';
type Revision = { id: string; revision: number; kind: ProviderKind; config: Record<string, unknown>; actor: string; reason: string; createdAt: string };
type Head = { id: string; activeRevision: number; revisions: Revision[] };
type ManagedHealth = { id: string; healthy: boolean; revision: number };
type Diagnostics = { healthy: boolean; metadata?: { displayName?: string; capabilities?: string[] }; mapping?: { field: string; column: string; databaseType?: string }[]; credentialReferencesVerified?: boolean; note?: string };
const base = '/api/v1/admin/auth/provider-wizard';
function defaults(kind: ProviderKind, id: string): Record<string, unknown> {
  const provisioning = { mode: 'explicit-only', defaultRole: 'player' };
  switch (kind) {
    case 'sql': return { id, displayName: id, driver: 'postgresql', dsnEnv: 'NEVERLAUNCHER_PROVIDER_DSN', table: 'users', columns: { id: 'id', username: 'username', email: 'email', password: 'password' }, password: { algorithm: 'argon2id' }, provisioning };
    case 'http': return { id, displayName: id, baseUrl: 'https://auth.example.org', issuer: 'https://auth.example.org', hostAllowlist: ['auth.example.org'], hmac: { secretEnv: 'NEVERLAUNCHER_PROVIDER_HMAC', keyId: 'primary' }, provisioning };
    case 'oidc': return { id, displayName: id, issuer: 'https://login.example.org', clientId: '', clientSecretEnv: 'NEVERLAUNCHER_PROVIDER_SECRET', redirectUris: [], hostAllowlist: ['login.example.org'], provisioning };
    case 'microsoft': return { id, displayName: id, cloud: 'public', tenant: 'consumers', clientId: '', clientSecretEnv: 'NEVERLAUNCHER_PROVIDER_SECRET', redirectUris: [], provisioning };
  }
}
export function AuthProviderWizard02910({ backendUrl, token }: { backendUrl: string; token: string }) {
  const [heads, setHeads] = useState<Head[]>([]);
  const [health, setHealth] = useState<ManagedHealth[]>([]);
  const [id, setId] = useState('external-users');
  const [kind, setKind] = useState<ProviderKind>('sql');
  const [rawConfig, setRawConfig] = useState(JSON.stringify(defaults('sql', 'external-users'), null, 2));
  const [reason, setReason] = useState('Configure external identity provider');
  const [test, setTest] = useState<Diagnostics | null>(null);
  const [testedConfig, setTestedConfig] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState<'config' | 'test' | 'activate'>('config');
  const load = useCallback(async () => {
    const result = await requestJSON<{ items: Head[] }>(backendUrl, base, token);
    setHeads(result.items || []);
    try { const current = await requestJSON<{items: ManagedHealth[]}>(backendUrl, `${base}/status`, token); setHealth(current.items || []); } catch { setHealth([]); }
  }, [backendUrl, token]);
  useEffect(() => { void load().catch(e => setError(String(e))); }, [load]);
  const request = (path: string, body: unknown) => requestJSON<Record<string, unknown>>(backendUrl, path, token, { method: 'POST', body: JSON.stringify(body) });
  const draft = () => {
    const config = JSON.parse(rawConfig) as Record<string, unknown>;
    if (!config || Array.isArray(config) || config.id !== id) throw new Error('Provider ID must match the configuration.');
    if (reason.trim().length < 3) throw new Error('Reason must contain at least 3 characters.');
    return { id, kind, config, reason: reason.trim() };
  };
  const perform = async (operation: () => Promise<void>) => {
    setError(''); setNotice(''); setBusy(true);
    try { await operation(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };
  const choose = (h: Head, rev?: Revision) => {
    const r = rev || h.revisions[0]; if (!r) return;
    setId(h.id); setKind(r.kind); setRawConfig(JSON.stringify(r.config, null, 2));
    setTest(null); setTestedConfig(''); setStep('config');
  };
  const changeKind = (value: ProviderKind) => {
    setKind(value); setRawConfig(JSON.stringify(defaults(value, id), null, 2)); setTest(null); setTestedConfig(''); setStep('config');
  };
  const changeId = (value: string) => {
    setId(value); try { const doc = JSON.parse(rawConfig) as Record<string, unknown>; doc.id = value; setRawConfig(JSON.stringify(doc, null, 2)); } catch { /* Draft JSON may be incomplete while editing. */ }
    setTest(null); setTestedConfig(''); setStep('config');
  };
  async function activateFor(h: Head, target: number) {
    if (reason.trim().length < 3) throw new Error('Reason is required.');
    await request(`${base}/${encodeURIComponent(h.id)}/activate`, { revision: target, expectedActiveRevision: h.activeRevision, reason: reason.trim() });
    await load(); setNotice(target === 0 ? `${h.id} disabled.` : `${h.id}: active revision #${target}.`);
  }

  return <section className="card wide" aria-label="Auth Provider Wizard">
    <div className="registryHeading"><h2>Auth Provider Wizard</h2><button disabled={busy} onClick={() => void perform(load)}>Обновить</button></div>
    <p className="muted">Настройка реальных SQL, HTTP, OIDC и Microsoft-провайдеров. Секреты и строки подключения задаются переменными окружения Backend; они не сохраняются в истории и не отображаются в Admin.</p>
    <h3>1. Конфигурация</h3>
    <div className="formGrid">
      <label>Provider ID<input value={id} onChange={e => changeId(e.target.value)} disabled={busy} /></label>
      <label>Тип<select value={kind} onChange={e => changeKind(e.target.value as ProviderKind)} disabled={busy}><option value="sql">SQL (PostgreSQL / MySQL / MariaDB)</option><option value="http">HTTP (signed)</option><option value="oidc">OIDC</option><option value="microsoft">Microsoft Entra</option></select></label>
    </div>
    <p className="muted">Укажите allowlist хостов, issuer, redirect URI, provisioning и имена переменных с секретами. Нельзя передавать DSN, пароли или private key в JSON.</p>
    <label>Конфигурация JSON<textarea rows={13} spellCheck={false} value={rawConfig} onChange={e => { setRawConfig(e.target.value); setTest(null); setTestedConfig(''); setStep('config'); }} style={{ width: '100%', fontFamily: 'monospace' }} /></label>
    <label>Причина изменения<input value={reason} onChange={e => setReason(e.target.value)} style={{width: '100%'}} /></label>
    <div className="buttonRow">
      <button disabled={busy} onClick={() => void perform(async () => {
        const report = await requestJSON<Diagnostics>(backendUrl, `${base}/test`, token, { method: 'POST', body: JSON.stringify(draft()) });
        if (!report.healthy) throw new Error('Provider is not healthy.');
        setTest(report); setTestedConfig(rawConfig); setStep('test'); setNotice('Test connection and SDK conformance succeeded.');
      })}>2. Test connection и mapping preview</button>
      <button disabled={busy || !test?.healthy || testedConfig !== rawConfig} onClick={() => void perform(async () => {
        const result = await request(`${base}/drafts`, draft()); await load(); setStep('activate'); setNotice(`Saved tested draft revision #${String(result.revision)}. You can now activate it after MFA.`);
      })}>Сохранить проверенный draft (MFA)</button>
    </div>
    {test && step !== 'config' && <div aria-label="Connection report"><h3>Проверка соединения</h3><p>Health: {test.healthy ? 'OK' : 'failed'} · Credentials: {test.credentialReferencesVerified ? 'проверены без раскрытия' : 'не проверены'}</p><p>Capabilities: {test.metadata?.capabilities?.join(', ') || '—'}</p>{test.mapping && <table className="table"><thead><tr><th>Поле</th><th>Колонка</th><th>Тип БД</th></tr></thead><tbody>{test.mapping.map(m => <tr key={m.field}><td>{m.field === 'password' ? 'password (без значений)' : m.field}</td><td>{m.column}</td><td>{m.databaseType || '—'}</td></tr>)}</tbody></table>}</div>}
    {notice && <p className="success" role="status">{notice}</p>}{error && <p className="error" role="alert">{error}</p>}
    <h3>3. Rollout и история ревизий</h3><p className="muted">Активация и откат требуют свежей phishing-resistant MFA и compare-and-swap версии. Новый коннектор проверяется непосредственно перед применением. При ошибке текущая конфигурация не изменяется.</p>
    {heads.length === 0 ? <p>Провайдеры пока не настроены.</p> : heads.map(h => <div key={h.id} className="card" style={{marginBottom: 12}}>
      <strong>{h.id}</strong> · active: {h.activeRevision === 0 ? 'disabled' : `#${h.activeRevision}`} · status: {h.activeRevision === 0 ? 'disabled' : (health.find(x => x.id === h.id)?.healthy === true ? 'healthy' : 'unverified / unavailable')}
      <div className="buttonRow"><button disabled={busy} onClick={() => choose(h)}>Редактировать</button><button disabled={busy || h.activeRevision === 0} onClick={() => void perform(async () => {setId(h.id); await activateFor(h, 0);})}>Отключить</button></div>
      <table className="table"><thead><tr><th>Revision</th><th>Тип</th><th>Дата</th><th>Операция</th></tr></thead><tbody>{h.revisions.map(rev => <tr key={rev.revision}><td>#{rev.revision}{rev.revision === h.activeRevision ? ' (active)' : ''}</td><td>{rev.kind}</td><td>{new Date(rev.createdAt).toLocaleString()}</td><td><button disabled={busy} onClick={() => choose(h, rev)}>Посмотреть</button> <button disabled={busy || rev.revision === h.activeRevision} onClick={() => void perform(() => activateFor(h, rev.revision))}>{rev.revision < h.activeRevision ? 'Rollback' : 'Activate'}</button></td></tr>)}</tbody></table>
    </div>)}
  </section>;
}
