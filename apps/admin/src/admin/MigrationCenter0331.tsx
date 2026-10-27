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
type Finding0332 = {code: string; severity: string; component: string; path?: string; message: string};
type Compatibility0332 = {sourceSha256:string; sourceEntries:number; claimedVersion?:string; detectedVersion?:string; versionStatus:string; versionEvidence:string; status:string; cutoverAllowed:boolean; components:{kind:string;path:string;status:string;type?:string}[]; findings:Finding0332[]; summary:Record<string,number>};
type Inventory0333 = {format:string; sourceSha256:string; sourceEntries:number; sourceBytes:number; totalBytes:number; sensitiveEntries:number; manifestSha256:string; categories:Record<string,number>; authProviders:Record<string,number>; textureProviders:Record<string,number>; optionalActions:Record<string,number>; serverReferences:number; files:{path:string;kind:string;size:number;sha256:string;sensitive?:boolean}[]};
type Identity0334 = {format:string;runId:string;sourceSha256:string;inventorySha256:string;entriesSha256:string;summary:Record<string,number>;ready:boolean;rows:{provider:string;sourceId:string;username:string;uuid:string;sourcePath:string;targetUserId?:string;status:string;reason:string}[]};
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
  const [source, setSource] = useState<File | null>(null);
  const [claimedVersion, setClaimedVersion] = useState('');
  const [compatibility, setCompatibility] = useState<Compatibility0332 | null>(null);
  const [inventory, setInventory] = useState<Inventory0333 | null>(null);
  const [identities,setIdentities] = useState<Identity0334|null>(null);
  const [error, setError] = useState('');
  const base = '/api/v1/admin/migration-runs';

  const refresh = useCallback(async (selectedId = runId) => {
    if (!projectId) return;
    const all = await requestJSON<Run[]>(backendUrl, `${base}?projectId=${encodeURIComponent(projectId)}`, token);
    setRuns(all);
    if (!selectedId) { setRun(null); setEvents([]); setCompatibility(null); setInventory(null); setIdentities(null); return; }
    const [current, journal] = await Promise.all([
      requestJSON<Run>(backendUrl, `${base}/${encodeURIComponent(selectedId)}`, token),
      requestJSON<Event[]>(backendUrl, `${base}/${encodeURIComponent(selectedId)}/events`, token)
    ]);
    setRun(current);
    setEvents(journal);
    try {setInventory(await requestJSON<Inventory0333>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/inventory`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setInventory(null); else throw e;}
    try {setIdentities(await requestJSON<Identity0334>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/identities`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setIdentities(null); else throw e;}
    try {setCompatibility(await requestJSON<Compatibility0332>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/compatibility`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setCompatibility(null); else throw e;}
  }, [backendUrl, token, projectId, runId]);

  useEffect(() => { setRunId(''); setRun(null); setEvents([]); setRuns([]); setCompatibility(null); setInventory(null); setIdentities(null); setError('');
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
  async function assess(event: React.FormEvent) {
    event.preventDefault(); if (!runId || !source || busy) return;
    if (source.size < 1 || source.size > 64 * 1024 * 1024) {setError('ZIP must be 1..64 MiB'); return;}
    setBusy(true);setError('');
    try {
      const result = await requestJSON<Compatibility0332>(backendUrl, `${base}/${encodeURIComponent(runId)}/compatibility`, token, {
        method: 'POST', headers: {'Content-Type':'application/zip','X-Gravit-Version':claimedVersion}, body:source
      });
      setCompatibility(result);await refresh(runId);
    } catch(e) {setError(String(e));await refresh(runId).catch(()=>undefined)}
    finally {setBusy(false)}
  }
  async function inventorySource() {
    if (!runId || !source || busy) return;
    if (source.size < 1 || source.size > 512 * 1024 * 1024) {setError('ZIP must be 1..512 MiB'); return;}
    setBusy(true);setError('');
    try {
      await requestJSON<Inventory0333>(backendUrl,`${base}/${encodeURIComponent(runId)}/inventory`,token,{
        method:'POST',headers:{'Content-Type':'application/zip'},body:source
      });
      await refresh(runId);
    } catch(e) {setError(String(e));await refresh(runId).catch(()=>undefined);}
    finally {setBusy(false)}
  }
  async function mapIdentities() {
    if (!runId || !source || !inventory || busy) return;
    setBusy(true);setError('');
    try {
      const result=await requestJSON<Identity0334>(backendUrl,`${base}/${encodeURIComponent(runId)}/identities`,token,{
        method:'POST',headers:{'Content-Type':'application/zip'},body:source
      });
      setIdentities(result);await refresh(runId);
    } catch(e){setError(String(e));await refresh(runId).catch(()=>undefined)} finally{setBusy(false)}
  }
  async function verifyIdentities() {
    if (!runId || busy || !identities) return;
    setBusy(true);setError('');
    try {
      await requestJSON<Identity0334>(backendUrl,`${base}/${encodeURIComponent(runId)}/identities/verify`,token,{method:'POST',body:'{}'});
      await refresh(runId);
    } catch(e){setError(String(e));await refresh(runId).catch(()=>undefined)}finally{setBusy(false)}
  }
  async function exportSource() {
    if (!runId || !source || busy || !inventory) return;
    if (source.size < 1 || source.size > 512 * 1024 * 1024) {setError('ZIP must be 1..512 MiB');return;}
    setBusy(true);setError('');
    try {
      const response=await fetch(`${backendUrl.replace(/\/$/,'')}${base}/${encodeURIComponent(runId)}/export`,{
        method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/zip'},body:source,cache:'no-store',redirect:'error'
      });
      if(!response.ok){const payload=await response.text();throw new Error(`Export HTTP ${response.status}: ${payload.slice(0,250)}`)}
      if(response.headers.get('X-Migration-Manifest-SHA256')!==inventory.manifestSha256) throw new Error('Export manifest mismatch');
      if(!(response.headers.get('Content-Type')||'').startsWith('application/zip')) throw new Error('Unexpected export response');
      const blob=await response.blob();const url=URL.createObjectURL(blob);
      try {const link=document.createElement('a');link.href=url;link.download=`gravit-source-${runId}.zip`;document.body.appendChild(link);link.click();link.remove();}
      finally {URL.revokeObjectURL(url)}
    } catch(e){setError(String(e))}finally{setBusy(false)}
  }
  return <section className="card wide" aria-label="Migration Center 0.33.4">
    <h2>Migration Center · 0.33.4</h2>
    <p>Durable workflow для проверки целевого проекта Never и фиксации инвентаризации. Статус «prepared» означает только сохранённый baseline; совместимость Gravit анализируется отдельно по ZIP; перенос пользователей и cutover не выполняются.</p>
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
    {run && <form onSubmit={e => void assess(e)} className="subcard">
      <h3>Gravit Compatibility Detector</h3>
      <p>Архив исходного проекта (LaunchServer.json, profiles/, runtime, modules/). Конфигурации и секреты не сохраняются на сервере. Неизвестные модули требуют проверки. Даже отчёт без блокеров не разрешает cutover.</p>
      <label className="field"><span>ZIP проекта Gravit (максимум 64 MiB)</span><input type="file" required accept=".zip,application/zip" onChange={e=>setSource(e.target.files?.[0]??null)}/></label>
      <label className="field"><span>Предполагаемая версия Gravit (не является подтверждением)</span><input value={claimedVersion} maxLength={40} onChange={e=>setClaimedVersion(e.target.value)} placeholder="5.7.12" /></label>
      <button type="submit" disabled={busy || !source || run.status !== 'prepared' || run.step !== 'source_assessment'}>Проверить ZIP и сохранить отчёт</button>
    </form>}
    {run && <article className="subcard">
      <h3>Source Inventory &amp; Export · MIG03</h3>
      <p>Инвентаризация использует выбранный ZIP (до 512 MiB), проверяет каждый файл и сохраняет только контрольные суммы и категории. Для экспорта нужно повторно предоставить тот же ZIP. Экспорт может содержать пароли и ключи: храните его в защищённом месте.</p>
      <div className="buttonRow">
        <button disabled={busy || !source || run.status!=='prepared' || run.step!=='source_assessment'} onClick={()=>void inventorySource()}>Инвентаризировать и сохранить</button>
        <button disabled={busy || !source || !inventory || run.status!=='prepared'} onClick={()=>void exportSource()}>Экспортировать проверенный ZIP</button>
      </div>
      {inventory && <>
        <p>Файлы: {inventory.sourceEntries}; распаковано: {inventory.totalBytes} байт; чувствительных файлов: {inventory.sensitiveEntries}; серверных записей: {inventory.serverReferences}.</p>
        <p>SHA-256 источника: <code>{inventory.sourceSha256}</code></p>
        <p>SHA-256 манифеста: <code>{inventory.manifestSha256}</code></p>
        <p>Категории: {JSON.stringify(inventory.categories)}; auth providers: {JSON.stringify(inventory.authProviders)}; optional actions: {JSON.stringify(inventory.optionalActions)}</p>
        <details><summary>Все файлы и контрольные суммы</summary><pre>{JSON.stringify(inventory.files,null,2)}</pre></details>
      </>}
    </article>}
    {run && <article className="subcard">
      <h3>Identity &amp; UUID Mapping · MIG04</h3>
      <p>Читает FileAuthSystem/Database.json либо sql-export/users.csv из исходного ZIP. Сопоставляет UUID с Never, блокирует конфликтные идентичности и не импортирует пароли. Для SQL нужен нормализованный CSV со столбцами id,username,uuid.</p>
      <div className="buttonRow">
        <button disabled={busy||!source||!inventory||run.status!=='prepared'} onClick={()=>void mapIdentities()}>Построить карту UUID</button>
        <button disabled={busy||!identities||run.status!=='prepared'} onClick={()=>void verifyIdentities()}>Повторно сверить с Never</button>
      </div>
      {identities && <>
        <p>Совпало: {identities.summary.matched??0}; ожидает импорта: {identities.summary.pending_import??0}; заблокировано: {identities.summary.blocked??0}. Все сопоставлены: {identities.ready?'да':'нет'}. Это не разрешение на cutover.</p>
        <details><summary>UUID mapping ({identities.rows.length})</summary><pre>{JSON.stringify(identities.rows,null,2)}</pre></details>
      </>}
    </article>}
    {compatibility && <article className="subcard">
      <h3>Совместимость: {compatibility.status}</h3>
      <p>Версия: {compatibility.detectedVersion??compatibility.claimedVersion??'не определена'} ({compatibility.versionStatus}, {compatibility.versionEvidence}); файлов: {compatibility.sourceEntries}. Cutover: запрещён.</p>
      <p>SHA-256 архива: <code>{compatibility.sourceSha256}</code></p>
      <ul>{compatibility.findings.map((finding,i)=><li key={i}><strong>{finding.severity}</strong> · {finding.code} · {finding.component} {finding.path} — {finding.message}</li>)}</ul>
      <details><summary>Классификация файлов</summary><pre>{JSON.stringify(compatibility.components,null,2)}</pre></details>
    </article>}
    {run && <article className="subcard" role="status">
      <p><strong>Статус:</strong> {run.status} · <strong>Текущий шаг:</strong> {run.step} · <strong>Revision:</strong> {run.revision} · <strong>Fence:</strong> {run.fence}</p>
      {run.lastError && <p className="error">{run.lastError}</p>}
      <details><summary>Зафиксированные результаты</summary><pre>{JSON.stringify(run.result,null,2)}</pre></details>
      <details open><summary>Журнал ({events.length})</summary><pre>{JSON.stringify(events,null,2)}</pre></details>
    </article>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>;
}
