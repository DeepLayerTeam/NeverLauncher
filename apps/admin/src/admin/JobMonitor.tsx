import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type Job = { id: string; kind: string; projectId: string; resourceId: string; status: string; attemptCount: number; maxAttempts: number; createdAt: string; updatedAt: string; lastError?: string; result?: Record<string, unknown> };
type Attempt = { attempt: number; status: string; startedAt: string; finishedAt?: string; error?: string };
const complete = new Set(['succeeded','failed','dead','revoked']);

/** Polls the durable job stored on the backend. A browser disconnect never cancels it. */
export function JobMonitor({ backendUrl, token, projectId, initialId = '', canPublish }: { backendUrl: string; token: string; projectId: string; initialId?: string; canPublish: boolean }) {
  const [jobId, setJobId] = useState(initialId);
  const [job, setJob] = useState<Job | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { setJobId(initialId); setJob(null); setAttempts([]); setError(''); }, [initialId, projectId]);
  useEffect(() => {
    if (!jobId.trim()) return;
    let active = true;
    async function load() {
      try {
        const id = encodeURIComponent(jobId.trim());
        const [next, history] = await Promise.all([
          requestJSON<Job>(backendUrl, `/api/v1/operations/${id}`, token),
          requestJSON<{ attempts: Attempt[] }>(backendUrl, `/api/v1/operations/${id}/attempts`, token),
        ]);
        if (active) {
          if (next.projectId !== projectId) { setError('Операция принадлежит другому проекту.'); setJob(null); return; }
          setJob(next); setAttempts(history.attempts ?? []); setError('');
        }
      } catch (e) { if (active) { setJob(null); setError(e instanceof Error ? e.message : String(e)); } }
    }
    void load();
    const interval = window.setInterval(() => { if (!complete.has(job?.status ?? '') && active) void load(); }, 2500);
    return () => { active = false; window.clearInterval(interval); };
  }, [backendUrl, token, jobId, projectId, job?.status]);
  async function change(action: 'cancel' | 'retry') {
    if (!job || !window.confirm(`${action}: ${job.id}?`)) return;
    setBusy(true);
    try { const next = await requestJSON<Job>(backendUrl, `/api/v1/operations/${encodeURIComponent(job.id)}/${action}`, token, { method: 'POST' }); setJob(next); setError(''); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  return <section className="subcard" aria-label="Монитор durable jobs">
    <h3>Job monitor</h3>
    <p className="muted">Отслеживание сохранённого задания. Закрытие вкладки не прерывает серверную операцию.</p>
    <label className="field">Correlation / Job ID<input aria-label="Job ID" value={jobId} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setJobId(e.target.value)} placeholder="ID операции" /></label>
    {job && <>
      <div className="summaryGrid"><article className="subcard"><strong>Состояние: {job.status}</strong><p>Операция: {job.kind}</p><p>Попытки: {job.attemptCount}/{job.maxAttempts}</p></article><article className="subcard"><strong>Correlation ID</strong><p><code>{job.id}</code></p><p>Обновлено: {job.updatedAt || '—'}</p></article></div>
      {job.lastError && <p role="alert" className="error">{job.lastError}</p>}
      {job.result && <details><summary>Результат</summary><pre>{JSON.stringify(job.result, null, 2)}</pre></details>}
      <div className="buttonRow">
        <button disabled={busy || !canPublish || job.status !== 'pending'} onClick={() => void change('cancel')}>Отменить ожидающее</button>
        <button disabled={busy || !canPublish || !['failed','dead','revoked'].includes(job.status)} onClick={() => void change('retry')}>Повторить</button>
      </div>
      <div className="tableScroll"><table className="table resourceTable"><thead><tr><th>Попытка</th><th>Статус</th><th>Начало</th><th>Завершение</th><th>Причина</th></tr></thead><tbody>{attempts.map(a => <tr key={a.attempt}><td>{a.attempt}</td><td>{a.status}</td><td>{a.startedAt}</td><td>{a.finishedAt || '—'}</td><td>{a.error || '—'}</td></tr>)}{attempts.length===0 && <tr><td colSpan={5}>Выполнение ещё не начиналось.</td></tr>}</tbody></table></div>
    </>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>;
}
