import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { TextInput } from '../components/primitives';

type Kind = 'channel-rollback' | 'package-publish';
type Job = { id: string; kind: Kind; status: string; lastError?: string; result?: Record<string, unknown>; attemptCount: number; maxAttempts: number; createdAt: string; completedAt?: string };
type Attempt = { attempt: number; status: string; startedAt: string; finishedAt?: string; error?: string };
type Validation = { valid: boolean; permission: string; effect: Record<string, string> };

export function OperationsWorkspace({ backendUrl, token, projectId, canPublish }: { backendUrl: string; token: string; projectId: string; canPublish: boolean }) {
  const [kind, setKind] = useState<Kind>('channel-rollback');
  const [profileId, setProfileId] = useState('vanilla');
  const [channel, setChannel] = useState('stable');
  const [toVersion, setToVersion] = useState('');
  const [packageId, setPackageId] = useState('');
  const [idempotencyKey, setIdempotencyKey] = useState(() => crypto.randomUUID());
  const [validation, setValidation] = useState<Validation | null>(null);
  const [jobId, setJobId] = useState('');
  const [job, setJob] = useState<Job | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const resetPreview = () => { setValidation(null); setIdempotencyKey(crypto.randomUUID()); };

  const request = { kind, projectId, resourceId: kind === 'package-publish' ? packageId : undefined, profileId, channel, toVersion, idempotencyKey };
  async function refresh(id = jobId) {
    if (!id) return;
    const current = await requestJSON<Job>(backendUrl, `/api/v1/operations/${encodeURIComponent(id)}`, token);
    setJob(current);
    const history = await requestJSON<{ attempts: Attempt[] }>(backendUrl, `/api/v1/operations/${encodeURIComponent(id)}/attempts`, token);
    setAttempts(history.attempts || []);
  }
  useEffect(() => { setJob(null); setJobId(''); setAttempts([]); setValidation(null); setIdempotencyKey(crypto.randomUUID()); }, [projectId]);
  useEffect(() => {
    if (!jobId || ['succeeded', 'failed', 'dead', 'revoked'].includes(job?.status ?? '')) return;
    let active = true;
    const id = window.setInterval(() => { if (active) refresh(jobId).catch(err => setError(String(err.message))); }, 2000);
    return () => { active = false; window.clearInterval(id); };
  }, [jobId, job?.status, token, backendUrl]);

  async function perform(action: 'validate' | 'execute') {
    setBusy(true); setError('');
    try {
      if (action === 'execute' && !validation?.valid) throw new Error('Сначала выполните validate.');
      if (action === 'execute' && !window.confirm(`Подтвердить ${kind} в проекте ${projectId}?\n${Object.entries(validation?.effect ?? {}).map(([k,v]) => `${k}: ${v}`).join('\n')}`)) return;
      const data = await requestJSON<Validation | Job>(backendUrl, `/api/v1/operations/${action}`, token, { method: 'POST', body: JSON.stringify(request) });
      if (action === 'validate') setValidation(data as Validation);
      else { const created = data as Job; setJobId(created.id); setJob(created); setAttempts([]); await refresh(created.id); }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  }
  async function modifyJob(action: 'cancel' | 'retry') {
    if (!job || !window.confirm(`${action} для операции ${job.id}?`)) return;
    setBusy(true); setError('');
    try {
      const next = await requestJSON<Job>(backendUrl, `/api/v1/operations/${encodeURIComponent(job.id)}/${action}`, token, { method: 'POST' });
      setJob(next); await refresh(job.id);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  }

  return <section className="card wide">
    <h2>Unified Operations · 0.21.7</h2>
    <p className="muted">Идемпотентные серверные операции. Результат и история сохраняются на Backend при закрытии браузера.</p>
    <div className="formGrid"><article className="subcard">
      <label className="field"><span>Операция</span><select value={kind} onChange={e => { setKind(e.target.value as Kind); resetPreview(); }}><option value="channel-rollback">Откат канала</option><option value="package-publish">Публикация пакета</option></select></label>
      <TextInput label="Проект" value={projectId} readOnly onChange={() => {}} />
      {kind === 'channel-rollback' ? <>
        <TextInput label="Профиль" value={profileId} onChange={v => { setProfileId(v); resetPreview(); }} />
        <TextInput label="Канал" value={channel} onChange={v => { setChannel(v); resetPreview(); }} />
        <TextInput label="Версия для отката" value={toVersion} onChange={v => { setToVersion(v); resetPreview(); }} />
      </> : <TextInput label="ID пакета" value={packageId} onChange={v => { setPackageId(v); resetPreview(); }} />}
      <TextInput label="Idempotency key (повтор использует тот же job)" value={idempotencyKey} onChange={v => { setIdempotencyKey(v); setValidation(null); }} />
      <div className="buttonRow"><button disabled={busy || !canPublish || !projectId} onClick={() => perform('validate')}>Проверить эффект</button><button disabled={busy || !canPublish || !validation?.valid} onClick={() => perform('execute')}>Выполнить</button></div>
      {validation && <div className="subcard"><p><strong>Проверка пройдена</strong> · {validation.permission}</p>{Object.entries(validation.effect).map(([key,value]) => <p key={key}><strong>{key}:</strong> {value}</p>)}</div>}
    </article>
    <article className="subcard">
      <h3>Задание и журнал исполнения</h3>
      <TextInput label="ID задания (для восстановления после перезагрузки)" value={jobId} onChange={v => { setJobId(v); setJob(null); setAttempts([]); }} />
      <div className="buttonRow"><button disabled={!jobId || busy} onClick={() => refresh().catch(err => setError(String(err.message)))}>Обновить</button>
        <button disabled={!canPublish || busy || job?.status !== 'pending'} onClick={() => modifyJob('cancel')}>Отменить ожидающее</button>
        <button disabled={!canPublish || busy || !['failed','revoked','dead'].includes(job?.status ?? '')} onClick={() => modifyJob('retry')}>Повторить</button>
      </div>
      {job && <><p><strong>Correlation ID:</strong> <code>{job.id}</code></p><p><strong>Состояние:</strong> {job.status} · попыток: {job.attemptCount}/{job.maxAttempts}</p>
        {job.lastError && <p className="error">{job.lastError}</p>}
        {job.result && <div><h4>Результат</h4>{Object.entries(job.result).filter(([,v]) => typeof v !== 'object').map(([key,value]) => <p key={key}>{key}: {String(value)}</p>)}</div>}
        <table className="table"><thead><tr><th>Попытка</th><th>Статус</th><th>Начало</th><th>Ошибка</th></tr></thead><tbody>{attempts.length ? attempts.map(a => <tr key={a.attempt}><td>{a.attempt}</td><td>{a.status}</td><td>{a.startedAt}</td><td>{a.error || '—'}</td></tr>) : <tr><td colSpan={4}>Попыток пока нет</td></tr>}</tbody></table>
      </>}
    </article></div>
    {error && <div role="alert" className="error">{error}</div>}
  </section>;
}
