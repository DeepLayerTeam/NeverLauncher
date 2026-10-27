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
type Credentials0335 = {format:string;runId:string;sourceSha256:string;identitySha256:string;imported:number;existingUnchanged:number;manualReset:number;complete:boolean;dryRun:boolean;rows:{provider:string;sourceId:string;username:string;uuid:string;state:string;reason?:string}[]};
type Security0336 = {format:string;runId:string;importedAccounts:number;existingNeverUntouched:number;manualResets:number;sessionsRevoked:number;devicesRevoked:number;challengesConsumed:number;hardwareEvidenceDeleted:number;measuredBootEvidenceDeleted:number;activeJwtKid:string;manifestPublicSha256:string;appliedAt?:string;verified:boolean;readyForCutover:boolean;requiresLogin:boolean;requiresDeviceEnrollment:boolean;requiresGuardAttestation:boolean};
type ContentPlan0337 = {format:string;sourceSha256:string;inventorySha256:string;profilePath:string;filesSha256:string;ready:boolean;blockers:string[];files:{sourcePath:string;targetPath:string;size:number;sha256:string;ownership:string}[];profile:{fields:{field:string;status:string;reason:string}[];settings:unknown};optional?:{ready:boolean;summary:Record<string,number>;fields:{field:string;status:string;reason:string}[]}};
type ContentState0337 = {plan:ContentPlan0337;workspaceId:string;workspaceRevision:number;state:string;stagedFiles:number;totalFiles:number;complete:boolean;validation:string;buildWorkspaceUrl:string};
type Modules0338 = {format:string;sourceSha256:string;inventorySha256:string;ready:boolean;cutoverAllowed:boolean;blockers:string[];modules:{path:string;sha256:string;name:string;implementation:string;status:string;reason:string;authHook:boolean;launchHook:boolean;sourcesPresent:boolean}[];wrappers:{path:string;mode:string;serverName?:string;legacyTokenPresent:boolean;legacyAddressPresent:boolean;replacement:string;status:string;reason:string}[]};
type Rehearsal03310 = {format:string;runId:string;stageId:string;sourceInventorySha256:string;sourceSnapshotSha256:string;targetSnapshotSha256:string;ready:boolean;cutoverAllowed:boolean;blockers:string[];probes:{name:string;passed:boolean;uuid?:string;evidenceSha256:string}[]};
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
  const [credentials,setCredentials] = useState<Credentials0335|null>(null);
  const [credentialPreview,setCredentialPreview] = useState<Credentials0335|null>(null);
  const [security,setSecurity]=useState<Security0336|null>(null);
  const [securityPreview,setSecurityPreview]=useState<Security0336|null>(null);
  const [freshKeysConfirmed,setFreshKeysConfirmed]=useState(false);
  const [securityRunConfirm,setSecurityRunConfirm]=useState('');
  const [contentProfilePath,setContentProfilePath] = useState('profiles/client.json');
  const [contentProfileId,setContentProfileId] = useState('gravit-client');
  const [contentProfileName,setContentProfileName] = useState('');
  const [contentLoader,setContentLoader] = useState('vanilla');
  const [contentVersion,setContentVersion] = useState('migrated-1');
  const [contentChannel,setContentChannel] = useState('stable');
  const [contentConfirm,setContentConfirm] = useState('');
  const [contentPreview,setContentPreview] = useState<ContentPlan0337|null>(null);
  const [contentState,setContentState] = useState<ContentState0337|null>(null);
  const [modules0338,setModules0338]=useState<Modules0338|null>(null);
  const [rehearsal03310,setRehearsal03310]=useState<Rehearsal03310|null>(null);
  const [wrapperPath0338,setWrapperPath0338]=useState('');
  const [bridgeNode0338,setBridgeNode0338]=useState('');
  const [bridgeName0338,setBridgeName0338]=useState('');
  const [bridgeKind0338,setBridgeKind0338]=useState('paper');
  const [bridgeProfile0338,setBridgeProfile0338]=useState('');
  const [bridgePublicKey0338,setBridgePublicKey0338]=useState('');
  const [bridgeConfirm0338,setBridgeConfirm0338]=useState('');
  const [bridgeFreshKeys0338,setBridgeFreshKeys0338]=useState(false);
  const [passwordFormat,setPasswordFormat] = useState('');
  const [confirmRun,setConfirmRun] = useState('');
  const [error, setError] = useState('');
  const base = '/api/v1/admin/migration-runs';

  const refresh = useCallback(async (selectedId = runId) => {
    if (!projectId) return;
    const all = await requestJSON<Run[]>(backendUrl, `${base}?projectId=${encodeURIComponent(projectId)}`, token);
    setRuns(all);
    if (!selectedId) { setRun(null); setEvents([]); setCompatibility(null); setInventory(null); setIdentities(null); setCredentials(null); return; }
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
    try {setCredentials(await requestJSON<Credentials0335>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/credentials`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setCredentials(null); else throw e;}
    try {setRehearsal03310(await requestJSON<Rehearsal03310>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/rehearsal`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setRehearsal03310(null); else throw e;}
    try {setModules0338(await requestJSON<Modules0338>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/modules`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setModules0338(null); else throw e;}
    try {setCompatibility(await requestJSON<Compatibility0332>(backendUrl,`${base}/${encodeURIComponent(selectedId)}/compatibility`,token));}
    catch (e) {if (e instanceof Error && 'status' in e && (e as {status?:number}).status === 404) setCompatibility(null); else throw e;}
  }, [backendUrl, token, projectId, runId]);

  useEffect(() => { setRunId(''); setRun(null); setEvents([]); setRuns([]); setCompatibility(null); setInventory(null); setIdentities(null); setCredentials(null); setCredentialPreview(null); setConfirmRun(''); setError('');
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
  async function migrationCredentials(commit: boolean) {
    if (!runId || !source || !identities || !inventory || busy) return;
    if (commit && (confirmRun !== runId || !credentialPreview)) {setError('Для импорта введите точный ID запуска и выполните предварительную проверку');return;}
    setBusy(true);setError('');
    try {
      const action=commit?'import':'preview';
      const report=await requestJSON<Credentials0335>(backendUrl,`${base}/${encodeURIComponent(runId)}/credentials/${action}`,token,{
        method:'POST',headers:{'Content-Type':'application/zip','X-Gravit-Password-Format':passwordFormat,
        ...(commit?{'X-Migration-Import-Confirm':runId}:{})},body:source
      });
      if(commit){setCredentials(report);setCredentialPreview(null);setConfirmRun('');await refresh(runId);}
      else setCredentialPreview(report);
    }catch(e){setError(String(e));await refresh(runId).catch(()=>undefined)}finally{setBusy(false)}
  }
  async function migrationSecurity0336(activate:boolean) {
    if(!runId||busy||!credentials) return;
    if(activate&&(!securityPreview||securityRunConfirm!==runId||!freshKeysConfirmed)) {
      setError('Для смены доверия сначала выполните preview, проверьте ключи и введите точный run ID');return;
    }
    setBusy(true);setError('');
    try {
      const result=await requestJSON<Security0336>(backendUrl,`${base}/${encodeURIComponent(runId)}/security/${activate?'activate':'preview'}`,token,{
        method:'POST',headers:activate?{'X-Migration-Trust-Confirm':runId,'X-Migration-Fresh-Keys-Confirmed':'true'}:undefined
      });
      if(activate){setSecurity(result);setSecurityPreview(null);setSecurityRunConfirm('');setFreshKeysConfirmed(false);await refresh(runId);}
      else setSecurityPreview(result);
    }catch(e){setError(String(e));}finally{setBusy(false);}
  }
  async function verifySecurity0336(){
    if(!runId||busy)return;
    setBusy(true);setError('');
    try { const result=await requestJSON<Security0336>(backendUrl,`${base}/${encodeURIComponent(runId)}/security`,token);setSecurity(result);}
    catch(e){setError(String(e))}finally{setBusy(false)}
  }
  async function migrationContent0337(commit:boolean) {
    if(!runId||!source||!inventory||busy)return;
    if(commit && (!contentPreview?.ready || contentConfirm!==runId)) {setError('Для переноса необходимо подтвердить текущий план и ID запуска');return;}
    setBusy(true);setError('');
    try {
      const headers={'Content-Type':'application/zip','X-Gravit-Profile-Path':contentProfilePath,'X-Never-Profile-ID':contentProfileId,
        'X-Never-Profile-Name':contentProfileName,'X-Never-Loader':contentLoader,'X-Never-Channel':contentChannel,'X-Never-Version':contentVersion,
        ...(commit?{'X-Migration-Content-Confirm':runId}:{})};
      const result=await requestJSON<ContentPlan0337|ContentState0337>(backendUrl,`${base}/${encodeURIComponent(runId)}/content/${commit?'import':'preview'}`,token,
        {method:'POST',headers,body:source});
      if(commit){setContentState(result as ContentState0337);setContentPreview(null);setContentConfirm('');}
      else {setContentPreview(result as ContentPlan0337);setContentState(null);}
    }catch(e){setError(String(e));}finally{setBusy(false);}
  }
  async function refreshMigrationContent0337() {
    if(!runId||!contentProfilePath||busy)return;
    setBusy(true);setError('');
    try {setContentState(await requestJSON<ContentState0337>(backendUrl,`${base}/${encodeURIComponent(runId)}/content?profilePath=${encodeURIComponent(contentProfilePath)}`,token));}
    catch(e){setError(String(e))}finally{setBusy(false)}
  }
  async function applyOptionals0337() {
    if(!runId||!contentProfilePath||busy||contentConfirm!==runId)return;
    setBusy(true);setError('');
    try {await requestJSON<unknown>(backendUrl,`${base}/${encodeURIComponent(runId)}/content/apply-optionals?profilePath=${encodeURIComponent(contentProfilePath)}`,token,
      {method:'POST',headers:{'X-Migration-Content-Confirm':runId}});await refresh(runId);}
    catch(e){setError(String(e))}finally{setBusy(false)}
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
  async function inspectModules0338(){
    if (!runId||!source||!inventory||busy) return;
    setBusy(true);setError('');
    try {
      const result=await requestJSON<Modules0338>(backendUrl,`${base}/${encodeURIComponent(runId)}/modules/analyze`,token,{method:'POST',headers:{'Content-Type':'application/zip'},body:source});
      setModules0338(result);await refresh(runId);
    } catch(e){setError(String(e));await refresh(runId).catch(()=>undefined)}finally{setBusy(false)}
  }
  async function enrollBridge0338(){
    if (!runId||!modules0338?.ready||bridgeConfirm0338!==runId||!bridgeFreshKeys0338||busy) return;
    setBusy(true);setError('');
    try {
      await requestJSON(backendUrl,`${base}/${encodeURIComponent(runId)}/modules/enroll-serverbridge`,token,{
        method:'POST',headers:{'X-Migration-Modules-Confirm':runId,'X-Migration-Fresh-Keys-Confirmed':'true'},
        body:JSON.stringify({wrapperPath:wrapperPath0338,id:bridgeNode0338,name:bridgeName0338,kind:bridgeKind0338,profileId:bridgeProfile0338,publicKey:bridgePublicKey0338})});
      setBridgeConfirm0338('');setBridgePublicKey0338('');setBridgeFreshKeys0338(false);await refresh(runId);
    }catch(e){setError(String(e))}finally{setBusy(false)}
  }
  return <section className="card wide" aria-label="Migration Center 0.33.7">
    <h2>Migration Center · 0.33.7</h2>
    <p>Durable workflow для проверки целевого проекта Never и фиксации инвентаризации. Статус «prepared» означает только сохранённый baseline; совместимость Gravit анализируется отдельно по ZIP; импорт поддерживаемых учётных записей доступен отдельно. Cutover не выполняется.</p>
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
      <label className="field"><span>ZIP проекта Gravit (максимум 64 MiB)</span><input type="file" required accept=".zip,application/zip" onChange={e=>{setSource(e.target.files?.[0]??null);setCredentialPreview(null);setConfirmRun('');}}/></label>
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
    {run && <article className="subcard">
      <h3>Authentication Migration · MIG05</h3>
      <p>Импортируются только новые local-аккаунты с проверенными исходными UUID и поддерживаемыми хешами. SQL: sql-export/users.csv с id,username,uuid,password_format,password_hash. Существующие аккаунты Never не перезаписываются. Неподдерживаемые SQL-хеши требуют индивидуального сброса.</p>
      <label className="field"><span>Формат хеша FileAuthSystem (обязательно при FileAuth, определяется оператором из конфигурации)</span>
        <select value={passwordFormat} onChange={e=>{setPasswordFormat(e.target.value);setCredentialPreview(null);}}>
          {['','sha256-hex','sha256-base64url','md5-hex','sha1-hex','sha512-hex','double-sha256-hex','double-sha256-binary-hex','phpass','bcrypt','argon2id'].map(x=><option key={x} value={x}>{x||'Нет FileAuth / только SQL'}</option>)}
        </select>
      </label>
      <div className="buttonRow">
        <button disabled={busy||!source||!identities||identities.summary.blocked>0||run.status!=='prepared'} onClick={()=>void migrationCredentials(false)}>Проверить импорт паролей (dry-run)</button>
      </div>
      {credentialPreview && <>
        <p>Dry-run: импортируемых {credentialPreview.imported}, существующих без изменений {credentialPreview.existingUnchanged}, индивидуальный сброс {credentialPreview.manualReset}.</p>
        <label className="field"><span>Для подтверждения введите ID запуска</span><input value={confirmRun} onChange={e=>setConfirmRun(e.target.value)} placeholder={runId}/></label>
        <button disabled={busy||confirmRun!==runId||run.status!=='prepared'} onClick={()=>void migrationCredentials(true)}>Подтверждаю реальный импорт аккаунтов</button>
      </>}
      <h3>Security &amp; Trust Reset · 0.33.6</h3>
      <p>Для новых импортированных пользователей: транзакционный отзыв всех старых сеансов Never, привязок устройств, challenges, TPM/measured-boot доказательств. Уже существующие Never-аккаунты не изменяются. Внешние ключи Gravit не импортируются. Cutover запрещён.</p>
      <div className="buttonRow">
        <button disabled={busy||!credentials||run.status!=='prepared'} onClick={()=>void migrationSecurity0336(false)}>Предварительная проверка reset</button>
        <button disabled={busy} onClick={()=>void verifySecurity0336()}>Проверить security receipt</button>
      </div>
      {securityPreview && <>
        <p>Предварительный reset для {securityPreview.importedAccounts} импортированных аккаунтов. Существующие Never-аккаунты без изменений: {securityPreview.existingNeverUntouched}. KID: {securityPreview.activeJwtKid}; SHA-256 публичного ключа: {securityPreview.manifestPublicSha256}.</p>
        <label className="field"><span>Введите точный run ID</span><input value={securityRunConfirm} onChange={e=>setSecurityRunConfirm(e.target.value)} autoComplete="off"/></label>
        <label className="field"><input type="checkbox" checked={freshKeysConfirmed} onChange={e=>setFreshKeysConfirmed(e.target.checked)}/> Подтверждаю, что активный JWT secret и manifest Ed25519 seed Never созданы независимо от Gravit и доставлены через защищённое хранилище секретов</label>
        <button disabled={busy||securityRunConfirm!==runId||!freshKeysConfirmed} onClick={()=>void migrationSecurity0336(true)}>Применить отзыв доверия</button>
      </>}
      {security && <p>Security reset: {security.verified?'проверен':'зафиксирован'} · sessions {security.sessionsRevoked} · devices {security.devicesRevoked} · challenges {security.challengesConsumed}. Требуются повторный вход, device enrollment и свежая Guard attestation.</p>}
      {credentials && <p>Зафиксированный результат: импортировано {credentials.imported}, существующих не изменено {credentials.existingUnchanged}, сброс пароля требуется {credentials.manualReset}. Это не разрешение на cutover.</p>}
      {(credentialPreview||credentials) && <details><summary>Отчёт (без секретов)</summary><pre>{JSON.stringify(credentialPreview||credentials,null,2)}</pre></details>}
    </article>}
    {run && <article className="subcard">
      <h3>Content &amp; Profile Migration · MIG07</h3>
      <p>Проверяемый перенос одного Gravit ClientProfile и содержимого updates/&lt;profile&gt;, clients/&lt;profile&gt;, libraries/, assets/ в зашифрованный Never Build Workspace. Сервер не выполняет исходные JAR и не копирует авторизацию, ключи или модули. Новый релиз подписывается только после отдельной проверки.</p>
      <label className="field"><span>Путь профиля в ZIP</span><input value={contentProfilePath} onChange={e=>{setContentProfilePath(e.target.value);setContentPreview(null)}} /></label>
      <label className="field"><span>ID нового профиля Never</span><input value={contentProfileId} onChange={e=>{setContentProfileId(e.target.value);setContentPreview(null)}} /></label>
      <label className="field"><span>Название</span><input value={contentProfileName} onChange={e=>{setContentProfileName(e.target.value);setContentPreview(null)}} /></label>
      <label className="field"><span>Загрузчик</span><select value={contentLoader} onChange={e=>{setContentLoader(e.target.value);setContentPreview(null)}}>{['vanilla','fabric','quilt','forge','neoforge'].map(x=><option key={x}>{x}</option>)}</select></label>
      <label className="field"><span>Канал</span><input value={contentChannel} onChange={e=>{setContentChannel(e.target.value);setContentPreview(null)}} /></label>
      <label className="field"><span>Версия нового релиза</span><input value={contentVersion} onChange={e=>{setContentVersion(e.target.value);setContentPreview(null)}} /></label>
      <div className="buttonRow">
        <button disabled={busy||!source||!inventory||run.status!=='prepared'} onClick={()=>void migrationContent0337(false)}>Проверить профиль и реальные файлы</button>
        <button disabled={busy||!runId} onClick={()=>void refreshMigrationContent0337()}>Проверить сохранённое состояние</button>
      </div>
      {contentPreview && <>
        <p>Профиль: {contentPreview.ready?'может быть перенесён':'заблокирован'}, файлов: {contentPreview.files.length}, optional: {contentPreview.optional?.ready?'преобразованы':contentPreview.optional?'есть блокеры':'не заданы'}.</p>
        {contentPreview.blockers.map((x,i)=><p key={i} className="error">{x}</p>)}
        <details><summary>План, поля и SHA-256</summary><pre>{JSON.stringify(contentPreview,null,2)}</pre></details>
        {contentPreview.ready && <>
          <label className="field"><span>Введите точный run ID перед переносом файлов</span><input autoComplete="off" value={contentConfirm} onChange={e=>setContentConfirm(e.target.value)} /></label>
          <button disabled={busy||contentConfirm!==runId} onClick={()=>void migrationContent0337(true)}>Перенести реальные файлы в зашифрованный Build Workspace</button>
        </>}
      </>}
      {contentState && <>
        <p>Workspace: <code>{contentState.workspaceId}</code>; сохранено {contentState.stagedFiles}/{contentState.totalFiles} файлов; состояние: {contentState.state}.</p>
        <p>Проверка: {contentState.validation||'требуется повторная проверка'}. Сборка и подпись выполняются через стандартные операции Build Workspace и Packages.</p>
        {contentState.plan.optional && <button disabled={busy||contentConfirm!==runId||contentState.state!=='built'} onClick={()=>void applyOptionals0337()}>Применить проверенный optional catalog к unsigned draft</button>}
      </>}
    </article>}
    {run && <article className="subcard">
      <h3>Module &amp; ServerWrapper Migration · MIG08</h3>
      <p>Статическая проверка JAR без запуска. Неизвестные исполняемые модули блокируют миграцию до переноса исходников либо сертифицированного адаптера. Старые ServerWrapper токены не применяются.</p>
      <button disabled={busy||!source||!inventory||run.status!=='prepared'} onClick={()=>void inspectModules0338()}>Проверить модули и ServerWrapper</button>
      {modules0338 && <>
        <p>Модулей: {modules0338.modules.length}, ServerWrapper: {modules0338.wrappers.length}, блокеров: {modules0338.blockers.length}. Cutover запрещён.</p>
        {modules0338.blockers.map((x,i)=><p key={i} className="error">{x}</p>)}
        <details><summary>Модули, SHA-256 и ServerWrapper</summary><pre>{JSON.stringify(modules0338,null,2)}</pre></details>
        {modules0338.ready&&modules0338.wrappers.length>0&&<>
          <p>Для подключения Never ServerBridge нужен новый Ed25519 publicKey; private key остаётся на игровом сервере. Регистрация не завершает проверку login/join.</p>
          <label className="field"><span>Файл ServerWrapper из отчёта</span><select value={wrapperPath0338} onChange={e=>setWrapperPath0338(e.target.value)}><option value="">Выберите</option>{modules0338.wrappers.map(x=><option key={x.path}>{x.path}</option>)}</select></label>
          <label className="field"><span>Новый ServerBridge node ID</span><input value={bridgeNode0338} onChange={e=>setBridgeNode0338(e.target.value)}/></label>
          <label className="field"><span>Название</span><input value={bridgeName0338} onChange={e=>setBridgeName0338(e.target.value)}/></label>
          <label className="field"><span>Kind</span><select value={bridgeKind0338} onChange={e=>setBridgeKind0338(e.target.value)}>{['paper','purpur','spigot','bukkit','fabric','forge','neoforge','velocity','bungeecord','waterfall','vanilla'].map(x=><option key={x}>{x}</option>)}</select></label>
          <label className="field"><span>Новый профиль Never</span><input value={bridgeProfile0338} onChange={e=>setBridgeProfile0338(e.target.value)}/></label>
          <label className="field"><span>Новый publicKey Ed25519 base64url</span><input value={bridgePublicKey0338} onChange={e=>setBridgePublicKey0338(e.target.value)}/></label>
          <label className="field"><input type="checkbox" checked={bridgeFreshKeys0338} onChange={e=>setBridgeFreshKeys0338(e.target.checked)}/> Независимый новый Ed25519 keypair Never, не унаследованный от Gravit</label>
          <label className="field"><span>Введите точный run ID (требуется свежая MFA-сессия)</span><input value={bridgeConfirm0338} onChange={e=>setBridgeConfirm0338(e.target.value)}/></label>
          <button disabled={busy||!wrapperPath0338||!bridgeNode0338||!bridgeProfile0338||!bridgePublicKey0338||bridgeConfirm0338!==runId||!bridgeFreshKeys0338} onClick={()=>void enrollBridge0338()}>Зарегистрировать новый ServerBridge node</button>
        </>}
      </>}
    </article>}
    {run && <article className="subcard">
      <h3>Isolated Migration Rehearsal · MIG10</h3>
      <p>Проверки исполняются CLI на отдельном изолированном стенде. Backend сверяет результаты с MIG03–MIG08 и UUID из сохранённой карты. Административный сервер не запускает JAR или команды из браузера.</p>
      <p><code>nl migrate gravit rehearse --run {runId} --stage /srv/staging-rehearsal --inventory-sha256 &lt;MIG03-manifest-sha256&gt; --backend https://your-never-backend --token &lt;token&gt;</code></p>
      <button disabled={busy} onClick={()=>void refresh(runId)}>Прочитать последнюю репетицию</button>
      {rehearsal03310 && <>
        <p>Стенд: <code>{rehearsal03310.stageId}</code> · проверок: {rehearsal03310.probes.length} · результат: {rehearsal03310.ready?'пройдена':'заблокирована'} · cutover: запрещён.</p>
        {rehearsal03310.blockers.map((x,i)=><p key={i} className="error">{x}</p>)}
        <details><summary>SHA-256, UUID и результаты проверок</summary><pre>{JSON.stringify(rehearsal03310,null,2)}</pre></details>
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
