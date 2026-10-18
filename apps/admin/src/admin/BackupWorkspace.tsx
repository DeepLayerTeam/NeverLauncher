import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';
import { auditHref } from './lifecycle';

type Backup = { backupId: string; sha256: string; size: number; createdAt: string };
type Status = { backups: Backup[]; mode: string; status: string };
type Inspection = { backupId: string; sha256: string; size: number; manifest: { databaseDump: boolean; storageObjects: number; createdAt: string; files: unknown[] } };
type DryRun = { status: string; backupId: string; checked: number; databaseDump: string; storageObjects: number; restoreMode: string };
type Restore = { status: string; backupId: string; safetyBackupId: string; restored: string[] };

export function BackupWorkspace({ backendUrl, token, canRestore }: { backendUrl: string; token: string; canRestore: boolean }) {
  const [data, setData] = useState<Status | null>(null);
  const [selected, setSelected] = useState('');
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [verified, setVerified] = useState<DryRun | null>(null);
  const [restore, setRestore] = useState<Restore | null>(null);
  const [database, setDatabase] = useState(false);
  const [storage, setStorage] = useState(false);
  const [confirmId, setConfirmId] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [search, setSearch] = useState('');
  const api = <T,>(path: string, init?: RequestInit) => requestJSON<T>(backendUrl, path, token, init);
  async function load() {
    const value = await api<Status>('/api/v1/operations/backup/status');
    setData(value);
  }
  useEffect(() => { let active = true; requestJSON<Status>(backendUrl, '/api/v1/operations/backup/status', token).then(value => { if (active) setData(value); }).catch(e => { if (active) setError(e.message); }); return () => { active = false; }; }, [backendUrl, token]);
  const choose = (id: string) => { setSelected(id); setInspection(null); setVerified(null); setRestore(null); setConfirmId(''); setDatabase(false); setStorage(false); setNotice(''); setError(''); };
  async function run(label: string, operation: () => Promise<void>) {
    setBusy(label); setError(''); setNotice('');
    try { await operation(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(''); }
  }
  function create() { void run('create', async () => {
    if (!window.confirm('Создать backup PostgreSQL и файлового хранилища? Операция может временно блокировать изменения.')) return;
    const result = await api<{ backupId: string }>('/api/v1/operations/backups', { method: 'POST' });
    choose(result.backupId); setNotice(`Backup ${result.backupId} создан и сохранён на Backend.`);
    try { await load(); } catch { setNotice(`Backup ${result.backupId} создан. Не удалось обновить список: проверьте его в Backend перед следующим действием.`); }
  }); }
  function inspect(id: string) { void run('inspect', async () => {
    const result = await api<Inspection>(`/api/v1/operations/backups/${encodeURIComponent(id)}`);
    setInspection(result); setVerified(null); setNotice('Метаданные архива получены; это ещё не проверка восстановимости.');
  }); }
  function dryRun() { void run('dry-run', async () => {
    const result = await api<DryRun>(`/api/v1/operations/backups/${encodeURIComponent(selected)}/restore-dry-run`, { method: 'POST' });
    if (result.backupId !== selected || result.status !== 'valid') throw new Error('Backend не подтвердил корректность выбранного архива.');
    setVerified(result); setNotice(`Проверка архива завершена. Проверено файлов: ${result.checked}. Восстановление не выполнялось.`);
  }); }
  function executeRestore() { void run('restore', async () => {
    if (!verified || verified.backupId !== selected || !canRestore || (!database && !storage) || confirmId !== selected) return;
    const parts = [database ? 'PostgreSQL' : '', storage ? 'Storage' : ''].filter(Boolean).join(' + ');
    if (!window.confirm(`НЕОБРАТИМО заменить ${parts} данными из ${selected}? Backend создаст safety backup до изменений. Текущие данные могут быть потеряны.`)) return;
    const result = await api<Restore>(`/api/v1/operations/backups/${encodeURIComponent(selected)}/restore`, { method: 'POST', body: JSON.stringify({ confirm: confirmId, database, storage }) });
    setRestore(result); setVerified(null); setConfirmId('');
    setNotice(`Ответ Backend: ${result.status}; восстановлено: ${result.restored?.join(', ') || 'неизвестно'}. Safety backup: ${result.safetyBackupId || 'не указан'}.`);
    try { await load(); } catch { setNotice(`Restore ответил ${result.status}; safety backup ${result.safetyBackupId || 'не указан'}. Не удалось обновить список — проверьте статус в аудите.`); }
  }); }
  const filtered = (data?.backups ?? []).filter(item => item.backupId.toLowerCase().includes(search.trim().toLowerCase()));
  const current = data?.backups?.find(item => item.backupId === selected);
  return <section className="card wide" aria-label="Резервное копирование и восстановление">
    <div className="registryHeading"><div><h2>Backup / Restore</h2><p className="muted">Настоящие архивы Backend; проверка SHA-256, dry-run и подтверждённое восстановление. Restore требует свежей phishing-resistant аутентификации.</p></div><div className="buttonRow"><button disabled={!!busy} onClick={() => void run('refresh', load)}>Обновить</button><button disabled={!!busy} onClick={create}>Создать backup</button></div></div>
    <p className="muted">Состояние: {data?.status ?? 'загрузка'} · Режим: {data?.mode ?? '—'} · Архивов: {data?.backups?.length ?? '—'}</p>
    {error && <p className="error" role="alert">{error} <span className="muted">Проверьте полномочия, соединение и повторите чтение статуса. Для restore подтвердите passkey.</span></p>}
    {notice && <p className="success" role="status">{notice}</p>}
    <a href={auditHref(selected || 'backup:')} >Открыть журнал аудита backup</a>
    <div className="dataToolbar"><label>Поиск по ID<input type="search" value={search} onChange={e => setSearch(e.target.value)} /></label></div>
    <div className="tableScroll"><table className="table resourceTable"><thead><tr><th>Backup</th><th>Создан</th><th>Размер</th><th>SHA-256</th><th>Действия</th></tr></thead><tbody>
      {filtered.map(item => <tr key={item.backupId}><td><code>{item.backupId}</code></td><td>{item.createdAt ? new Date(item.createdAt).toLocaleString() : '—'}</td><td>{(item.size / 1024 / 1024).toFixed(1)} MiB</td><td><code>{item.sha256.slice(0, 18)}…</code></td><td><button disabled={!!busy} onClick={() => { choose(item.backupId); inspect(item.backupId); }}>Открыть</button></td></tr>)}
      {filtered.length === 0 && <tr><td colSpan={5}>Архивов нет либо поиск ничего не нашёл.</td></tr>}
    </tbody></table></div>
    {selected && current && <article className="subcard">
      <h3>Backup {selected}</h3>
      <p>Серверный SHA-256: <code>{current.sha256}</code></p>
      <div className="buttonRow"><button disabled={!!busy} onClick={() => inspect(selected)}>Инспектировать</button><button disabled={!!busy} onClick={dryRun}>Проверить восстановимость (dry-run)</button><a href={auditHref(selected)}>Аудит этого архива</a></div>
      {inspection && <div><p>Файлы: {inspection.manifest.files?.length ?? 0} · PostgreSQL: {inspection.manifest.databaseDump ? 'есть' : 'нет'} · Storage objects: {inspection.manifest.storageObjects}</p><p className="muted">Манифест прочитан. Для восстановления обязательно выполните dry-run.</p></div>}
      {verified && <div className="subcard"><h4>Результат restore dry-run: {verified.status}</h4><p>Проверено файлов: {verified.checked} · PostgreSQL dump: {verified.databaseDump} · Storage: {verified.storageObjects}</p><p className="muted">Dry-run подтверждает структуру архива, но не гарантирует успешность destructive restore при других внешних условиях.</p></div>}
      <div className="subcard">
        <h4>Восстановить данные</h4>
        <p className="muted">Доступно только после успешного dry-run. Backend создаёт safety backup. Операция синхронная, не является durable job; при обрыве соединения сначала проверьте состояние и аудит, не повторяйте запрос автоматически.</p>
        <label><input type="checkbox" checked={database} onChange={e => setDatabase(e.target.checked)} disabled={!canRestore || verified?.databaseDump !== 'valid' || !inspection?.manifest.databaseDump} /> PostgreSQL</label>
        <label><input type="checkbox" checked={storage} onChange={e => setStorage(e.target.checked)} disabled={!canRestore || !verified} /> Storage</label>
        <label className="field">Введите ID архива точно<input value={confirmId} onChange={e => setConfirmId(e.target.value)} autoComplete="off" placeholder={selected}/></label>
        {!canRestore && <p className="muted">Требуются глобальные права settings:manage и свежий passkey step-up.</p>}
        <button className="danger" disabled={!!busy || !canRestore || !verified || !inspection || confirmId !== selected || (!database && !storage)} onClick={executeRestore}>Выполнить подтверждённое восстановление</button>
      </div>
      {restore && <article className="subcard"><h4>Ответ restore: {restore.status}</h4><p>Затронуто: {restore.restored?.join(', ') || '—'}</p><p>Safety backup: <code>{restore.safetyBackupId || 'не указан'}</code></p><a href={auditHref(selected)}>Проверить результат в аудите</a></article>}
    </article>}
  </section>;
}
