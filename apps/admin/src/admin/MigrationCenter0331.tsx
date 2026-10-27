import React, { useCallback, useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type Run = {
  id: string;
  projectId: string;
  status: 'pending' | 'running' | 'failed' | 'paused' | 'prepared';
  step: string;
  revision: number;
  fence: number;
  lastError?: string;
  result: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};
type Event = { sequence: number; kind: string; step: string; revision: number; detail: unknown; createdAt: string };

/** A working server-backed migration run operator. No client-side state is
 * considered authoritative. All mutations are fenced/committed on Backend. */
export function MigrationCenter0331({backendUrl, token, projectId}: {backendUrl: string; token: string; projectId: string}) {
  const [key, setKey] = useState('');
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState('');
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const base = '/api/v1/admin/migration-runs';

  const refresh = useCallback(async (selectedId = runId) => {
    if (!projectId) return;
    const all = await requestJSON<Run[]>(backendUrl, `${base}?projectId=${encodeURIComponent(projectId)}`, token);
    setRuns(all);
    if (!selectedId) { setRun(null); setEvents([]); return; }
    const [current, journal] = await Promise.all([
      requestJSON<Run>(backendUrl, `${base}/${encodeURIComponent(selectedId)}`, token),
      requestJSON<Event[]>(backendUrl, `${base}/${encodeURIComponent(selectedId)}/events`, token)
    ]);
    setRun(current);
    setEvents(journal);
  }, [backendUrl, token, projectId, runId]);

  useEffect(() => { setRunId(''); setRun(null); setEvents([]); setRuns([]); setError('');
    if (projectId) void requestJSON<Run[]>(backendUrl,`${base}?projectId=${encodeURIComponent(projectId)}`,token)
      .then(setRuns).catch((e: Error) => setError(e.message));
  }, [backendUrl, token, projectId]);

  async function create(event: React.FormEvent) {
    event.preventDefault(); if (!projectId || key.length < 8 || busy) return;
    setBusy(true); setError('');
    try {
      const saved = await requestJSON<Run>(backendUrl, base, token, {
        method: 'POST', body: JSON.stringify({projectId, sourceKind: 'gravit', idempotencyKey: key})
      });
      setRunId(saved.id); await refresh(saved.id);
    } catch (e) { setError(String(e)); } finally { setBusy(false); }
    // Preserve the idempotency key after uncertain network errors for safe retry.
  }
  async function operate(action: 'execute' | 'pause' | 'resume') {
    if (!runId || busy) return;
    setBusy(true); setError('');
    try {
      await requestJSON<Run>(backendUrl, `${base}/${encodeURIComponent(runId)}/${action}`, token, {method: 'POST',body: '{}'});
      await refresh(runId);
    } catch (e) {
      // Failed/indeterminate responses require rereading durable state before replay.
      setError(String(e));
      await refresh(runId).catch(() => undefined);
    } finally { setBusy(false); }
  }
  return <section className="card wide" aria-label="Migration Center 0.33.1">
    <h2>Migration Center · 0.33.1</h2>
    <p>Durable workflow для проверки целевого проекта Never и фиксации инвентаризации. Статус «prepared» означает только сохранённый baseline; совместимость Gravit, перенос пользователей и cutover пока не выполняются.</p>
    <form onSubmit={e => void create(e)} className="subcard">
      <label className="field"><span>Проект назначения</span><input value={projectId} readOnly /></label>
      <label className="field"><span>Ключ идемпотентности (сохраните до завершения операции)</span>
        <input value={key} minLength={8} maxLength={128} required onChange={e => setKey(e.target.value)} placeholder="change-request-2026-001" /></label>
      <button type="submit" disabled={busy || !projectId || key.length < 8}>Создать или найти запуск</button>
    </form>
    <label className="field"><span>Запуск</span><select value={runId} onChange={e => {setRunId(e.target.value);void refresh(e.target.value).catch(err=>setError(String(err)));}}>
      <option value="">Выберите run</option>
      {runs.map(item => <option key={item.id} value={item.id}>{item.id} · {item.status} · {item.step}</option>)}
    </select></label>
    <div className="buttonRow">
      <button disabled={busy || !runId} onClick={() => void refresh(runId).catch(e=>setError(String(e)))}>Обновить</button>
      <button disabled={busy || !runId || !run || !['pending','running'].includes(run.status)} onClick={() => void operate('execute')}>Выполнить baseline</button>
      <button disabled={busy || !runId || !run || !['pending','failed','running'].includes(run.status)} onClick={() => void operate('pause')}>Пауза</button>
      <button disabled={busy || !runId || !run || !['paused','failed'].includes(run.status)} onClick={() => void operate('resume')}>Возобновить</button>
    </div>
    {run && <article className="subcard" role="status">
      <p><strong>Статус:</strong> {run.status} · <strong>Текущий шаг:</strong> {run.step} · <strong>Revision:</strong> {run.revision} · <strong>Fence:</strong> {run.fence}</p>
      {run.lastError && <p className="error">{run.lastError}</p>}
      <details><summary>Зафиксированные результаты</summary><pre>{JSON.stringify(run.result,null,2)}</pre></details>
      <details open><summary>Журнал ({events.length})</summary><pre>{JSON.stringify(events,null,2)}</pre></details>
    </article>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>;
}
