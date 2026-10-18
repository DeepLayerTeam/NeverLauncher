import React, { useCallback, useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { recoveryAdvice } from './lifecycle';

type Event = { id: string; actor: string; action: string; target: string; createdAt: string; ip?: string; userAgent?: string; correlationId?: string; reasonCode?: string; jobId?: string };
type Result = { items: Event[]; total: number; limit: number; offset: number };
export const reasonAdvice: Record<string, string> = {
  insufficient_permissions: 'Обратитесь к владельцу за нужной ролью/разрешением.',
  authentication_required: 'Выполните вход заново.',
  invalid_input: 'Проверьте введённые поля.',
  invalid_field: 'Исправьте значение поля и повторите.',
  revision_conflict: 'Обновите данные: ревизия изменена другой сессией.',
  service_unavailable: 'Дождитесь восстановления сервера и повторите просмотр.',
  applied: 'Настройка применена. Откройте ревизию в редакторе конфигурации.',
};
const defaultFilters = { search: '', actor: '', action: '', target: '', correlationId: '', reasonCode: '', jobId: '', from: '', to: '' };
type Filters = typeof defaultFilters;
function initialFilters(): Filters { const query = new URLSearchParams(window.location.hash.split('?')[1] || ''); return { ...defaultFilters, search: query.get('query') || '' }; }
export function AuditWorkspace({ backendUrl, token }: { backendUrl: string; token: string }) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [applied, setApplied] = useState<Filters>(initialFilters);
  const [result, setResult] = useState<Result>({ items: [], total: 0, limit: 25, offset: 0 });
  const [page, setPage] = useState(0);
  const [limit, setLimit] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { const update = () => { const next = initialFilters(); setFilters(next); setApplied(next); setPage(0); }; window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  const reload = useCallback(async (signal?: AbortSignal) => {
    const q = new URLSearchParams({ offset: String(page * (limit || result.limit || 25)) });
    if (limit > 0) q.set('limit', String(limit));
    for (const [key, value] of Object.entries(applied)) if (value.trim()) q.set(key, key === 'from' || key === 'to' ? new Date(value).toISOString() : value.trim());
    const data = await requestJSON<Result>(backendUrl, `/api/v1/admin/audit?${q}`, token, { signal });
    setResult(data); setError('');
  }, [backendUrl, token, applied, page, limit, result.limit]);
  useEffect(() => { const ctrl = new AbortController(); setBusy(true); void reload(ctrl.signal).catch(e => { if (!ctrl.signal.aborted) setError(`${e.message}. ${recoveryAdvice(e.message)}`); }).finally(() => { if (!ctrl.signal.aborted) setBusy(false); }); return () => ctrl.abort(); }, [reload]);
  function edit(key: keyof Filters, value: string) { setFilters(old => ({ ...old, [key]: value })); }
  const effectivePageSize = limit || result.limit || 25;
  const totalPages = Math.max(1, Math.ceil(result.total / effectivePageSize));
  return <section className="card wide"><div className="registryHeading"><div><h2>Аудит</h2><p className="muted">Поиск и пагинация на Backend. Для старых событий задайте дату начала вручную. Права доступа контролируются сервером.</p></div><button disabled={busy} onClick={() => void reload().catch(e => setError(e.message))}>Обновить</button></div>
    <form onSubmit={e => { e.preventDefault(); setPage(0); setApplied({ ...filters }); }}>
      <div className="auditFilters">{([['search', 'Поиск'], ['actor', 'Инициатор'], ['action', 'Действие'], ['target', 'Объект'], ['correlationId', 'Correlation ID'], ['reasonCode', 'Причина отказа'], ['jobId', 'Job ID']] as const).map(([key, label]) => <label className="field" key={key}>{label}<input value={filters[key]} maxLength={200} onChange={e => edit(key, e.target.value)} /></label>)}<label className="field">От (локальное время)<input type="datetime-local" value={filters.from} onChange={e => edit('from', e.target.value)} /></label><label className="field">До (локальное время)<input type="datetime-local" value={filters.to} onChange={e => edit('to', e.target.value)} /></label></div>
      <div className="buttonRow"><button type="submit">Искать</button><button type="button" onClick={() => { setFilters(defaultFilters); setApplied(defaultFilters); setPage(0); }}>Сбросить</button><label>Строк на странице <select value={limit} onChange={e => {setLimit(Number(e.target.value));setPage(0);}}><option value={0}>Настройка сервера</option><option value={10}>10</option><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label></div>
    </form>
    {error && <p role="alert" className="error">{error}</p>}
    <p className="muted">Найдено: {result.total} · {busy ? 'Загрузка…' : `страница ${page + 1} из ${totalPages}`}</p>
    <div className="tableScroll"><table className="table resourceTable"><thead><tr><th>Время</th><th>Инициатор</th><th>Операция</th><th>Объект</th><th>Причина / действие</th><th>Связи</th></tr></thead><tbody>{result.items.map(event => <tr key={event.id}><td>{event.createdAt}</td><td>{event.actor || '—'}</td><td>{event.action}</td><td><code>{event.target || '—'}</code></td><td>{event.reasonCode ? <><strong>{event.reasonCode}</strong><p className="muted">{reasonAdvice[event.reasonCode] || 'Проверьте подробности в журнале и статус связанной операции.'}</p></> : '—'}</td><td>{event.correlationId ? <div><a href={`#/audit?query=${encodeURIComponent(event.correlationId)}`}>Correlation</a></div> : null}{event.jobId ? <div><a href={`#/job-monitor?job=${encodeURIComponent(event.jobId)}`}>Job: {event.jobId}</a></div> : null}<details><summary>Технические поля</summary><pre>{JSON.stringify(event, null, 2)}</pre></details></td></tr>)}{result.items.length === 0 && <tr><td colSpan={6}>Нет событий для выбранных фильтров.</td></tr>}</tbody></table></div>
    <div className="pager"><button disabled={page === 0 || busy} onClick={() => setPage(v => v - 1)}>Назад</button><span>Страница {page + 1} / {totalPages}</span><button disabled={(page + 1) * effectivePageSize >= result.total || busy} onClick={() => setPage(v => v + 1)}>Далее</button></div>
  </section>;
}
