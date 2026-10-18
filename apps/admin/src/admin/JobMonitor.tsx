import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { auditHref, recoveryAdvice } from './lifecycle';

type Job = { id: string; kind: string; action: string; projectId: string; resourceId: string; status: string; attemptCount: number; maxAttempts: number; createdAt: string; updatedAt: string; lastError?: string; result?: Record<string, unknown> };
type Attempt = { id: number; attempt: number; status: string; startedAt: string; finishedAt?: string; error?: string };
type Page = { items: Job[]; hasMore: boolean; offset: number; limit: number };
const terminal = new Set(['succeeded', 'failed', 'dead', 'revoked']);
const states = ['', 'pending', 'running', 'succeeded', 'failed', 'revoked', 'dead'];

/** Backend is authoritative. Disconnection and browser reload do not cancel work. */
export function JobMonitor({ backendUrl, token, projectId, initialId = '', canPublish }: { backendUrl: string; token: string; projectId: string; initialId?: string; canPublish: boolean }) {
  const [jobId, setJobId] = useState(() => initialId || new URLSearchParams(window.location.hash.split('?')[1] || '').get('job') || '');
  const [job, setJob] = useState<Job | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [page, setPage] = useState<Page | null>(null);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const api = <T,>(path: string, init?: RequestInit) => requestJSON<T>(backendUrl, path, token, init);
  const explain = (e: unknown) => { const reason = e instanceof Error ? e.message : String(e); return `${reason}. ${recoveryAdvice(reason)}`; };
  async function reloadPage(nextOffset = offset, nextFilter = filter) {
    const params = new URLSearchParams({ projectId, limit: '25', offset: String(nextOffset) });
    if (nextFilter) params.set('status', nextFilter);
    setPage(await api<Page>(`/api/v1/operations/jobs?${params.toString()}`));
  }
  async function load(id = jobId) {
    if (!id.trim()) return;
    const encoded = encodeURIComponent(id.trim());
    const [current, history] = await Promise.all([
      api<Job>(`/api/v1/operations/${encoded}`),
      api<{ attempts: Attempt[] }>(`/api/v1/operations/${encoded}/attempts`),
    ]);
    if (current.projectId !== projectId) throw new Error('Операция относится к другому проекту.');
    setJob(current); setAttempts(history.attempts ?? []);
  }
  useEffect(() => { setJob(null); setAttempts([]); setPage(null); setOffset(0); setFilter(''); setError(''); setJobId(initialId || new URLSearchParams(window.location.hash.split('?')[1] || '').get('job') || ''); }, [projectId, initialId]);
  useEffect(() => {
    if (!projectId) return;
    let live = true;
    const params = new URLSearchParams({ projectId, limit: '25', offset: String(offset) }); if (filter) params.set('status', filter);
    requestJSON<Page>(backendUrl, `/api/v1/operations/jobs?${params}`, token).then(data => { if(live) setPage(data); }).catch(e => { if(live) setError(explain(e)); });
    return () => { live = false; };
  }, [projectId, filter, offset, backendUrl, token]);
  useEffect(() => {
    if (!jobId.trim()) return;
    let live = true;
    const currentID = jobId.trim();
    async function poll() {
      try {
        const path = encodeURIComponent(currentID);
        const [next, history] = await Promise.all([
          requestJSON<Job>(backendUrl, `/api/v1/operations/${path}`, token),
          requestJSON<{ attempts: Attempt[] }>(backendUrl, `/api/v1/operations/${path}/attempts`, token),
        ]);
        if(live) {
          if(next.projectId !== projectId) { setJob(null); setError('Операция относится к другому проекту.'); return; }
          setJob(next); setAttempts(history.attempts??[]); setError('');
        }
      } catch(e) { if(live) setError(explain(e)); }
    }
    void poll();
    const interval = terminal.has(job?.status ?? '') ? undefined : window.setInterval(() => { if(live) void poll(); }, 3000);
    return () => { live = false; if (interval !== undefined) window.clearInterval(interval); };
  }, [backendUrl, token, projectId, jobId, job?.status]);
  function select(id: string) {
    setJobId(id); setJob(null); setAttempts([]); setError(''); setNotice('');
    window.location.hash = `/job-monitor?job=${encodeURIComponent(id)}`;
  }
  async function modify(action: 'cancel'|'retry') {
    if (!job || !canPublish) return;
    if (!window.confirm(`${action === 'cancel' ? 'Отменить ожидающее задание' : 'Повторить завершившееся с ошибкой задание'} ${job.id}?\nРезультат будет сохранён Backend.`)) return;
    setBusy(true); setNotice(''); setError('');
    try {
      const updated = await api<Job>(`/api/v1/operations/${encodeURIComponent(job.id)}/${action}`, { method: 'POST' });
      setJob(updated); setNotice(`Backend подтвердил ${action}. Статус: ${updated.status}.`);
      await Promise.all([load(job.id), reloadPage()]);
    } catch (e) { setError(explain(e)); } finally { setBusy(false); }
  }
  return <section className="card wide" aria-label="Монитор durable jobs">
    <div className="registryHeading"><div><h2>Jobs — жизненный цикл операций</h2><p className="muted">Задания выполняются на Backend независимо от браузера. Отмена возможна только до начала исполнения; ошибка не означает безопасного автоматического повтора.</p></div><button disabled={busy} onClick={() => { void reloadPage().catch(e => setError(explain(e))); void load().catch(e => setError(explain(e))); }}>Обновить</button></div>
    {error && <p className="error" role="alert">{error}</p>}{notice && <p className="success" role="status">{notice}</p>}
    <div className="dataToolbar"><label>Статус<select value={filter} onChange={e => { setFilter(e.target.value); setOffset(0); }}>{states.map(s => <option key={s} value={s}>{s || 'Все'}</option>)}</select></label><label>Job ID<input value={jobId} onChange={e => setJobId(e.target.value)} placeholder="job_..." /></label><button disabled={!jobId.trim()} onClick={() => void load().catch(e => setError(explain(e)))}>Открыть по ID</button></div>
    <div className="tableScroll"><table className="table resourceTable"><thead><tr><th>Задание</th><th>Ресурс</th><th>Состояние</th><th>Попытки</th><th>Обновлено</th><th>Просмотр</th></tr></thead><tbody>{(page?.items ?? []).map(j => <tr key={j.id}><td><code>{j.id}</code><br/>{j.kind}</td><td>{j.resourceId}</td><td><span className={`badge ${j.status === 'succeeded' ? 'ok' : ['dead','failed'].includes(j.status) ? 'warn' : ''}`}>{j.status}</span></td><td>{j.attemptCount}/{j.maxAttempts}</td><td>{j.updatedAt ? new Date(j.updatedAt).toLocaleString() : '—'}</td><td><button onClick={() => select(j.id)}>Открыть</button></td></tr>)}{!page?.items?.length && <tr><td colSpan={6}>Для выбранного проекта и фильтра заданий нет.</td></tr>}</tbody></table></div>
    <div className="pager"><span>Показано: {page?.items?.length ?? 0}, смещение: {offset}</span><div><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset-25))}>Назад</button><button disabled={!page?.hasMore} onClick={() => setOffset(offset+25)}>Далее</button></div></div>
    {job && <article className="subcard">
      <h3>Job {job.id}</h3><p>Операция: {job.kind} · ресурс: {job.resourceId} · <strong>{job.status}</strong></p>
      <p className="muted">Обновлено: {job.updatedAt || '—'} · Попыток: {job.attemptCount}/{job.maxAttempts}</p>
      {job.lastError && <p className="error" role="alert">Причина: {job.lastError} · {recoveryAdvice(job.lastError)}</p>}
      {job.status === 'running' && <p>Исполнитель выполняет операцию. Не отправляйте повторный запрос.</p>}
      {job.status === 'pending' && <p>Ожидает исполнения. Можно отменить до начала работы.</p>}
      <div className="buttonRow"><button disabled={busy || !canPublish || job.status !== 'pending'} onClick={() => void modify('cancel')}>Отменить ожидающее</button><button disabled={busy || !canPublish || !['failed','dead','revoked'].includes(job.status)} onClick={() => void modify('retry')}>Повторить</button><a href={auditHref(job.id)}>Аудит по correlation ID</a></div>
      {job.result && <details><summary>Ответ Backend</summary><pre>{JSON.stringify(job.result, null, 2)}</pre></details>}
      <h4>История попыток</h4><div className="tableScroll"><table className="table resourceTable"><thead><tr><th>№</th><th>Состояние</th><th>Начало</th><th>Завершение</th><th>Ошибка</th></tr></thead><tbody>{attempts.map(a => <tr key={a.id || a.attempt}><td>{a.attempt}</td><td>{a.status}</td><td>{a.startedAt ? new Date(a.startedAt).toLocaleString() : '—'}</td><td>{a.finishedAt ? new Date(a.finishedAt).toLocaleString() : '—'}</td><td>{a.error || '—'}</td></tr>)}{attempts.length===0 && <tr><td colSpan={5}>Попыток пока нет.</td></tr>}</tbody></table></div>
    </article>}
  </section>;
}
