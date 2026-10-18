import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type Event = { id?: string; actor?: string; action?: string; target?: string; createdAt?: string; ip?: string; [key: string]: unknown };
export function AuditWorkspace({ backendUrl, token }: { backendUrl: string; token: string }) {
  const [items, setItems] = useState<Event[]>([]);
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.hash.split('?')[1] || '').get('query') || '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(0);
  async function refresh() { const result = await requestJSON<{ items: Event[] }>(backendUrl, '/api/v1/admin/audit', token); setItems(result.items ?? []); }
  useEffect(() => { let live = true; requestJSON<{ items: Event[] }>(backendUrl, '/api/v1/admin/audit', token).then(v => { if (live) setItems(v.items ?? []); }).catch(e => { if(live) setError(e.message); }); return () => { live = false; }; }, [backendUrl, token]);
  useEffect(() => { const update = () => {setQuery(new URLSearchParams(window.location.hash.split('?')[1]||'').get('query')||''); setPage(0);};window.addEventListener('hashchange',update);return()=>window.removeEventListener('hashchange',update);}, []);
  const search = query.trim().toLowerCase();
  const filtered = search ? items.filter(e => `${e.id} ${e.actor} ${e.action} ${e.target} ${e.createdAt}`.toLowerCase().includes(search)) : items;
  return <section className="card wide"><div className="registryHeading"><div><h2>Аудит операций</h2><p className="muted">Поиск по объекту, корреляции, действию и инициатору. Отсутствие записи по ID не доказывает, что синхронная операция не выполнялась.</p></div><button disabled={busy} onClick={() => {setBusy(true); refresh().catch(e => setError(e.message)).finally(()=>setBusy(false));}}>Обновить</button></div>
    {error && <p className="error">{error}</p>}
    <div className="dataToolbar"><label>Поиск в аудите<input type="search" value={query} onChange={e => {setQuery(e.target.value);setPage(0);}} /></label><button onClick={() => {setQuery('');setPage(0);}}>Сбросить</button></div>
    <p className="muted">Найдено: {filtered.length}. В результат входят только возвращённые Backend события.</p>
    <div className="tableScroll"><table className="table resourceTable"><thead><tr><th>Время</th><th>Инициатор</th><th>Операция</th><th>Объект / ID</th><th>Детали</th></tr></thead><tbody>{filtered.slice(page*25,(page+1)*25).map((event,i) => <tr key={`${event.id??i}-${page}`}><td>{event.createdAt || '—'}</td><td>{event.actor || '—'}</td><td>{event.action || '—'}</td><td><code>{event.target || '—'}</code></td><td><details><summary>Поля</summary><pre>{JSON.stringify(event,null,2)}</pre></details></td></tr>)}{!filtered.length && <tr><td colSpan={5}>Совпадений нет.</td></tr>}</tbody></table></div>
    <div className="pager"><span>Страница {page+1} / {Math.max(1,Math.ceil(filtered.length/25))}</span><div><button disabled={page===0} onClick={()=>setPage(page-1)}>Назад</button><button disabled={(page+1)*25>=filtered.length} onClick={()=>setPage(page+1)}>Далее</button></div></div>
  </section>;
}
