import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { prepareOwnerOperation, observeOwnerOperation, readOwnerPending, saveOwnerPending, clearOwnerPending, recoveryStorageKey, type OwnerIntent, type OwnerPending, type OwnerCheck, type ChannelHead, openStagedRollback } from './owner-lifecycle-03513.ts';
import { auditHref, recoveryAdvice } from './lifecycle.ts';
import { ReleaseApi, type Draft, type DraftFields, type PackageInfo, type Preview, type ValidationReport, type PublishBlocker0385 } from '../api/release';
import { ApiError } from '../api/client';
import { PublishReadiness0385 } from './PublishReadiness0385';
import { JobMonitor } from './JobMonitor';
import { ValidationHistory03412 } from './ValidationHistory03412';
import { BuildWorkspacePanel } from './BuildWorkspacePanel';
import { ComponentGraphEditor0248 } from './ComponentGraphEditor0248';

type Step = 'project'|'profile'|'build'|'verify'|'channel';
const steps: Array<{id: Step; title:string}> = [
  {id:'project',title:'Проект'}, {id:'profile',title:'Профиль и загрузчик'}, {id:'build',title:'Сборка и файлы'}, {id:'verify',title:'Проверка и подпись'}, {id:'channel',title:'Публикация и откат'},
];
const empty = (projectId:string, profileId = '', channel = 'stable'): DraftFields => ({projectId,profileId,channel,version:'',minecraftVersion:'',loader:'vanilla',packageId:'',jobId:'',step:'project'});
const printable = (e:unknown) => e instanceof Error ? e.message : String(e);
const isPassed = (v: ValidationReport | null) => v?.integrity?.result === 'passed';

export function ReleaseWorkspace({backendUrl,token,projectId,initialProfileId='',initialChannel='',canPrepare,canFileWrite,canPublish}: {backendUrl:string;token:string;projectId:string;initialProfileId?:string;initialChannel?:string;canPrepare:boolean;canFileWrite:boolean;canPublish:boolean}) {
  const api = useMemo(() => new ReleaseApi(backendUrl,token),[backendUrl,token]);
  const [drafts,setDrafts] = useState<Draft[]>([]);
  const [draft,setDraft] = useState<Draft|null>(null);
  const [form,setForm] = useState<DraftFields>(empty(projectId,initialProfileId,initialChannel||'stable'));
  const [step,setStep] = useState<Step>('project');
  const [profiles,setProfiles] = useState<Array<{id:string;name:string;loader:string;minecraftVersion?:string;loaderVersion?:string;javaMajor?:number}>>([]);
  const [releases,setReleases] = useState<Array<{id:string;version:string;profileId:string;channel:string;status:string}>>([]);
  const [channelHead,setChannelHead] = useState<ChannelHead|null>(null);
  const [channelHeadError,setChannelHeadError] = useState('');
  const [packageInfo,setPackageInfo] = useState<PackageInfo|null>(null);
  const [report,setReport] = useState<ValidationReport|null>(null);
  const [refusal,setRefusal] = useState<PublishBlocker0385[]>([]);
  const [policy,setPolicy] = useState<ValidationReport['policy']|null>(null);
  const [preview,setPreview] = useState<Preview|null>(null);
  const [rollbackPreview,setRollbackPreview] = useState<Preview|null>(null);
  const [planned,setPlanned] = useState<{pending:OwnerPending;preview:Preview}|null>(null);
  const recoveryKey = useMemo(() => recoveryStorageKey(backendUrl,projectId,sessionStorage.getItem('neverlauncher.admin.sessionId')||'unknown-session'),[backendUrl,projectId,token]);
  const [pending,setPending] = useState<OwnerPending|null>(null);
  const [check,setCheck] = useState<OwnerCheck|null>(null);
  const [targetVersion,setTargetVersion] = useState('');
  const [monitorId,setMonitorId] = useState('');
  const [uploadFile,setUploadFile] = useState<File|null>(null);
  const [uploadPath,setUploadPath] = useState('');
  const [uploadOwnership,setUploadOwnership] = useState<'required'|'managed'|'optional'>('required');
  const [catalogRefresh,setCatalogRefresh] = useState(0);
  const [catalogBlocking,setCatalogBlocking] = useState(false);
  const [busy,setBusy] = useState(false);
  const operationLock=useRef(false);
  const [notice,setNotice] = useState('');
  const [error,setError] = useState('');
  const [dirty,setDirty] = useState(false);
  const refreshDrafts = useCallback(async () => { const items = await api.drafts(projectId); setDrafts(items.items ?? []); },[api,projectId]);
  const loadChecks = useCallback(async (id:string) => {
    const [info,checks] = await Promise.all([api.package(id),api.validations(id)]);
    setPackageInfo(info);setReport(checks);setRefusal([]);
  },[api]);
  useEffect(() => {
    let live=true;
    const recovered=readOwnerPending(sessionStorage,recoveryKey,projectId);
    setPending(recovered);setCheck(null);setPlanned(null);
    setDraft(null);setForm(empty(projectId,initialProfileId,initialChannel||'stable'));setDrafts([]);setStep('project');setPackageInfo(null);setReport(null);setRefusal([]);setPreview(null);setRollbackPreview(null);setMonitorId(recovered?.jobId||'');setDirty(false);
    if (!projectId || !canPrepare) return;
    Promise.all([api.drafts(projectId),api.profiles(projectId),api.releases(projectId),api.policy(projectId)])
      .then(([ds,ps,vs,p])=>{if(live){setDrafts(ds.items??[]);setProfiles(ps.items??[]);setReleases(vs.items??[]);setPolicy(p);
        setForm(current=>current.packageId||current.jobId ? current : {...current,profileId:ps.items?.some(x=>x.id===initialProfileId)?initialProfileId:current.profileId,channel:initialChannel||current.channel, ...(ps.items?.find(x=>x.id===initialProfileId)?.minecraftVersion?{minecraftVersion:ps.items.find(x=>x.id===initialProfileId)!.minecraftVersion!,loader:ps.items.find(x=>x.id===initialProfileId)!.loader}:{})});}})
      .catch(e=>{if(live)setError(printable(e));});
    return ()=>{live=false};
  },[api,projectId,canPrepare,recoveryKey]);
  // Keep a fresh, unsaved draft aligned with the owner's explicit navigation.
  useEffect(()=>{
    if (!draft && !dirty && !pending && !form.packageId)
      setForm(current=>({...current,profileId:profiles.some(p=>p.id===initialProfileId)?initialProfileId:current.profileId,channel:initialChannel||current.channel,...(profiles.find(p=>p.id===initialProfileId)?.minecraftVersion?{minecraftVersion:profiles.find(p=>p.id===initialProfileId)!.minecraftVersion!,loader:profiles.find(p=>p.id===initialProfileId)!.loader}:{})}));
  },[initialProfileId,initialChannel,profiles]);
  function edit(key:keyof DraftFields,value:string) {
    if (form.packageId && ['profileId','channel','version','loader','minecraftVersion'].includes(key)) { setError('Поля сборки закреплены за созданным пакетом. Для изменения создайте новый черновик.');return; }
    setForm(v=>({...v,[key]:value}));setDirty(true);setPreview(null);setRollbackPreview(null);setPlanned(null);setError('');
  }
  async function perform<T>(action:()=>Promise<T>,success:string):Promise<T|undefined> {
    if (operationLock.current || busy) return;
    operationLock.current=true;setBusy(true);setError('');setNotice('');setRefusal([]);
    try { const result=await action();setNotice(success);return result; }
    catch(e){if(e instanceof ApiError && e.blockers.length)setRefusal(e.blockers);setError(printable(e));return undefined;}
    finally{operationLock.current=false;setBusy(false)}
  }
  function loadDraft(d:Draft){
    if (dirty && !window.confirm('Несохранённые изменения будут потеряны. Продолжить?')) return;
    setDraft(d);setForm({projectId:d.projectId,profileId:d.profileId,channel:d.channel,version:d.version,minecraftVersion:d.minecraftVersion,loader:d.loader,packageId:d.packageId,jobId:d.jobId,step:d.step});
    setStep(steps.some(s=>s.id===d.step)?d.step as Step:'project');setMonitorId(pending?.jobId||d.jobId);
    if(d.packageId && !d.jobId && !pending?.jobId)void api.linkedJob(d.id).then(job=>setMonitorId(job.id)).catch(()=>undefined);
    setDirty(false);setPreview(null);setRollbackPreview(null);setPlanned(null);
    setPackageInfo(null);setReport(null);setRefusal([]);setTargetVersion('');
    if(d.packageId) void loadChecks(d.packageId).catch(e=>setError(printable(e)));
  }
  async function save(nextStep?:Step): Promise<Draft|undefined> {
    const fields={...form,step:nextStep||step};
    const updated=await perform(async()=>draft ? api.save({...draft,...fields}) : api.create(fields),'Черновик сохранён на Backend.');
    if(updated){setDraft(updated);setForm(fields);setStep(fields.step as Step);setDirty(false);await refreshDrafts();}
    return updated;
  }
  async function removeDraft(){if(!draft || !window.confirm('Удалить сохранённый черновик? Пакет и задание при этом НЕ удаляются.'))return;
    const done=await perform(()=>api.remove(draft.id),'Черновик удалён.');if(done){setDraft(null);setForm(empty(projectId));setStep('project');setPackageInfo(null);setReport(null);setMonitorId(pending?.jobId||'');setDirty(false);setPlanned(null);await refreshDrafts();}
  }
  async function createPackage(){
    if(!draft || dirty) {setError('Сначала сохраните черновик.');return}
    if(!form.profileId || !form.version.trim() || !form.minecraftVersion.trim()){setError('Укажите профиль, Minecraft и версию сборки.');return}
    const info=await perform(async()=>{
      let pkg:PackageInfo;
      try {pkg=await api.createPackage(form)}
      catch(err){
        // Reattach to an existing exact package after a lost response. A mismatch is rejected by the draft binding.
        const id=`${projectId}-${form.profileId}-${form.version}`;
        try {pkg=await api.package(id)} catch{throw err}
        if(pkg.projectId!==projectId || pkg.profileId!==form.profileId || pkg.channel!==form.channel || pkg.version!==form.version || pkg.minecraft?.version!==form.minecraftVersion || pkg.minecraft?.loader!==form.loader)throw err;
      }
      const saved=await api.save({...draft,...form,packageId:pkg.packageId,step:'build'});
      setDraft(saved);setForm(v=>({...v,packageId:pkg.packageId,step:'build'}));setDirty(false);setPackageInfo(pkg);setStep('build');await refreshDrafts();return pkg;
    },'Реальный пакет создан и привязан к черновику.');
    if(info)await loadChecks(info.packageId).catch(e=>setError(printable(e)));
  }
  async function upload(){if(!uploadFile||!form.packageId)return;
    const result=await perform(()=>api.upload(form.packageId,uploadFile,uploadPath||uploadFile.name,uploadOwnership),'Файл загружен и SHA-256 проверен Backend.');
    if(result){setUploadFile(null);setUploadPath('');setCatalogRefresh(v=>v+1);await loadChecks(form.packageId).catch(e=>setError(printable(e)));}
  }
  async function packageAction(action:'validate'|'sign'|'stage'|'integrity-check'){
    if(!form.packageId)return;
    if(action==='sign' && catalogBlocking){setError('Необходимо сохранить изменения каталога и пройти проверку Backend до подписи.');return}
    setPlanned(null);setPreview(null);setRollbackPreview(null);
    await perform(async()=>{
      const result=await api.packageAction<{status?:string;checks?:Array<{id:string;status:string;reasonCode?:string;message:string}>;blockers?:PublishBlocker0385[]}>(form.packageId,action);
      await loadChecks(form.packageId);
      if(action==='validate' && result.status!=='valid') {
        const blockers=result.blockers??result.checks?.filter(x=>x.status!=='ok').map(x=>({reasonCode:x.reasonCode||'file-validation-failed',resource:x.id,message:x.message,action:'Исправьте файл и повторите Validate.'}))??[];
        throw new ApiError(409,'Validate завершился отказом. Исправьте перечисленные ошибки.', 'file-validation-failed',blockers);
      }
      return result;
    },`${action}: проверка Backend успешно завершена.`);
  }
  async function submitEvidence(file:File){
    if(!form.packageId)return;
    await perform(async()=>{
      if(file.size>1024*1024)throw new Error('Evidence file превышает 1 МБ.');
      const data:unknown=JSON.parse(await file.text());
      const result=await api.evidence(form.packageId,data);
      await loadChecks(form.packageId);return result;
    },'Подписанное runtime evidence проверено Backend.');
  }
  function newIntent(kind:'package-publish'|'channel-rollback'):OwnerIntent {
    return {kind,projectId,profileId:form.profileId,channel:form.channel,
      ...(kind==='package-publish'?{resourceId:form.packageId}:{toVersion:targetVersion}),
      idempotencyKey:crypto.randomUUID()};
  }
  async function validate(kind:'package-publish'|'channel-rollback'){
    if(pending){setError('Сначала завершите проверку сохранённой операции.');return;}
    setPlanned(null);setPreview(null);setRollbackPreview(null);
    const next=await perform(async()=>{
      const intent=newIntent(kind);
      const result=await prepareOwnerOperation(api,intent);
      setPlanned({pending:{intent,before:result.before},preview:result.preview});
      return result.preview;
    },'Backend проверил полномочия и эффект. Публикация ещё не выполнена.');
    if(kind==='package-publish')setPreview(next||null);else setRollbackPreview(next||null);
  }
  async function execute(kind:'package-publish'|'channel-rollback'){
    if(!planned || planned.pending.intent.kind!==kind || !planned.preview.valid || !draft || dirty || pending)return;
    const exact=planned.pending;
    const effect=Object.entries(planned.preview.effect||{}).map(([k,v])=>`${k}: ${v}`).join('\n');
    if(!window.confirm(`Подтвердите ${kind} в проекте ${projectId}:\n${effect}`))return;
    const job=await perform(async()=>{
      // Re-read the head immediately before submission. Backend will also check
      // the revision in its worker, even if it changes after this read.
      const latest=await api.channelHead(exact.intent.projectId,exact.intent.profileId,exact.intent.channel);
      if(latest.revision!==exact.before.revision || latest.releaseId!==exact.before.releaseId)
        throw Error('Канал изменился после preview. Обновите и повторите проверку.');
      // BEFORE network I/O. An ACK loss must not produce a second operation.
      saveOwnerPending(sessionStorage,recoveryKey,exact);setPending(exact);
      const accepted=await api.executeOperation(exact.intent);
      if(accepted.projectId!==projectId || accepted.kind!==kind || !accepted.id)
        throw Error('Backend вернул несоответствующий job; проверьте журнал по idempotency key.');
      const recorded={...exact,jobId:accepted.id};
      saveOwnerPending(sessionStorage,recoveryKey,recorded);setPending(recorded);setMonitorId(accepted.id);
      return accepted;
    },'Операция поставлена в очередь. Ожидайте исполнения и проверки channel head.');
    setPlanned(null);setPreview(null);setRollbackPreview(null);
    if(job && kind==='package-publish'){
      // Failure to update the draft does not lose the persisted operation.
      const saved=await perform(()=>api.save({...draft,...form,step:'channel',jobId:job.id}),'Job привязан к черновику.');
      if(saved){setDraft(saved);setForm(v=>({...v,step:'channel',jobId:job.id}));setDirty(false);await refreshDrafts();}
    }
  }
  async function recoverOperation(){
    if(!pending || busy)return;
    const recorded=await perform(async()=>{
      // User-triggered replay with EXACT same key and payload, never a new key.
      const accepted=await api.executeOperation(pending.intent);
      if(!accepted.id || accepted.projectId!==pending.intent.projectId || accepted.kind!==pending.intent.kind)
        throw Error('Ответ Backend не совпадает с исходной операцией');
      const next={...pending,jobId:accepted.id};
      saveOwnerPending(sessionStorage,recoveryKey,next);setPending(next);setMonitorId(accepted.id);
      return accepted;
    },'Получен идентификатор исходного durable job. Публикация ещё не подтверждена.');
    return recorded;
  }
  useEffect(()=>{
    if(!pending?.jobId)return;
    let live=true;
    const observed=pending;
    async function inspect(){
      try{
        const state=await observeOwnerOperation(api,observed);
        if(!live)return;
        setCheck(state);
        if(state.phase==='confirmed'){
          api.releases(projectId).then(r=>{if(live)setReleases(r.items??[])}).catch(()=>undefined);
        }
      }catch(e){if(live)setError(printable(e)+' · Проверьте durable job и аудит.');}
    }
    void inspect();
    const timer=window.setInterval(()=>{if(live)void inspect();},3000);
    return ()=>{live=false;window.clearInterval(timer)};
  },[api,pending?.jobId,recoveryKey,projectId]);
  async function continueStagedRollback(){
    if(!pending || !check || check.phase!=='staged' || !canPrepare)return;
    if(dirty && !window.confirm('Текущие несохранённые изменения будут потеряны. Открыть подготовленный rollback?'))return;
    const created=await perform(async()=>{
      const {draft:newDraft,fields}=await openStagedRollback(api,pending,check);
      setDraft(newDraft);setForm(fields);setStep('verify');setDirty(false);setPlanned(null);
      await refreshDrafts();await loadChecks(fields.packageId);
      return newDraft;
    },'Черновик подготовленного rollback открыт. Для stable нужна новая полная runtime-сертификация до публикации.');
    return created;
  }
  function acknowledgeOperation(){
    if(!pending || !check || !['confirmed','failed','staged','unconfirmed'].includes(check.phase))return;
    if((check.phase==='unconfirmed' || check.phase==='staged') && !window.confirm('Канал не подтверждён или откат только подготовлен. Вы проверили журнал и дальнейшие действия?'))return;
    clearOwnerPending(sessionStorage,recoveryKey);setPending(null);setCheck(null);setPlanned(null);
  }
  useEffect(()=>{
    let live=true;setChannelHead(null);setChannelHeadError('');
    if(!projectId||!form.profileId||!form.channel)return;
    api.channelHead(projectId,form.profileId,form.channel)
      .then(value=>{if(live)setChannelHead(value)})
      .catch(e=>{if(live)setChannelHeadError(printable(e))});
    return ()=>{live=false};
  },[api,projectId,form.profileId,form.channel,check?.phase]);
  async function refreshChannel(){
    try{setChannelHead(await api.channelHead(projectId,form.profileId,form.channel));setChannelHeadError('')}
    catch(e){setChannelHead(null);setChannelHeadError(printable(e))}
  }
  const rollbackTargets=releases.filter(v=>v.status==='published' && v.profileId===form.profileId && v.channel===form.channel && v.id!==channelHead?.releaseId);
  return <section className="card wide releaseWorkspace">
    <h2>Release Workspace · {__NEVERLAUNCHER_VERSION__}</h2>
    <p className="muted">Мастер: проект → профиль и загрузчик → сборка → проверка → канал. Черновики хранятся на Backend с проверкой версии при сохранении.</p>
    <div className="formGrid"><article className="subcard">
      <h3>Черновики проекта {projectId || '—'}</h3>
      <div className="buttonRow"><button disabled={busy || !canPrepare} onClick={()=>{if(dirty && !window.confirm('Отменить несохранённые изменения?'))return;setDraft(null);setForm(empty(projectId));setStep('project');setPackageInfo(null);setReport(null);setMonitorId(pending?.jobId||'');setDirty(false);setPlanned(null);}}>Новый черновик</button><button disabled={busy} onClick={()=>void refreshDrafts().catch(e=>setError(printable(e)))}>Обновить</button></div>
      <ul className="releaseDraftList">{drafts.map(d=><li key={d.id}><button aria-current={draft?.id===d.id?'page':undefined} onClick={()=>loadDraft(d)}>{d.version || 'Без версии'} · {d.profileId || 'Без профиля'} · {d.step} <small>({new Date(d.updatedAt).toLocaleString()})</small></button></li>)}</ul>
      {drafts.length===0 && <p className="muted">Черновиков нет. Укажите параметры и сохраните новый.</p>}
      {draft && <p>Черновик: <code>{draft.id}</code> · revision {draft.revision}</p>}
      <div className="buttonRow"><button disabled={busy||!canPrepare} onClick={()=>void save()}>Сохранить {dirty?'изменения':'черновик'}</button><button disabled={!draft||busy} className="danger" onClick={()=>void removeDraft()}>Удалить черновик</button></div>
    </article><article className="subcard"><h3>Этапы выпуска</h3><nav className="releaseSteps" aria-label="Этапы выпуска">{steps.map(item=><button key={item.id} type="button" aria-current={step===item.id?'step':undefined} onClick={()=>{setStep(item.id);setPreview(null);setRollbackPreview(null);setPlanned(null);}}>{item.title}</button>)}</nav><p>{dirty?'Есть несохранённые изменения.':'Данные синхронизированы с последним сохранением.'}</p></article></div>
    {step==='project' && <article className="subcard"><h3>1. Проект</h3><p>Выбранный проект: <strong>{projectId}</strong>. Переключение выполняется в верхней панели Admin. Черновики доступны только своему владельцу с правом release:prepare.</p><button disabled={busy||!projectId||!canPrepare} onClick={()=>void save('profile')}>Сохранить и перейти к профилю</button></article>}
    {step==='profile' && <article className="subcard"><h3>2. Профиль / загрузчик / Minecraft</h3>
      <label className="field">Профиль<select disabled={!!form.packageId} value={form.profileId} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>{const found=profiles.find(p=>p.id===e.target.value);setForm(v=>({...v,profileId:e.target.value,loader:found?.loader||v.loader,minecraftVersion:found?.minecraftVersion||''}));setDirty(true);}}><option value="">Выберите профиль</option>{profiles.map(p=><option key={p.id} value={p.id}>{p.name||p.id} ({p.id})</option>)}</select></label>
      <label className="field">Загрузчик<select disabled={!!form.packageId||!!profiles.find(p=>p.id===form.profileId)?.minecraftVersion} value={form.loader} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>edit('loader',e.target.value)}>{['vanilla','fabric','quilt','forge','neoforge'].map(x=><option key={x} value={x}>{x}</option>)}</select></label>
      <label className="field">Версия Minecraft<input disabled={!!form.packageId||!!profiles.find(p=>p.id===form.profileId)?.minecraftVersion} placeholder="1.21.1" value={form.minecraftVersion} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('minecraftVersion',e.target.value)} /></label>
      {profiles.find(p=>p.id===form.profileId)?.minecraftVersion && <p className="muted" role="status">Профиль закрепляет Minecraft {profiles.find(p=>p.id===form.profileId)?.minecraftVersion}, загрузчик {profiles.find(p=>p.id===form.profileId)?.loader} {profiles.find(p=>p.id===form.profileId)?.loaderVersion||''} и Java {profiles.find(p=>p.id===form.profileId)?.javaMajor}. Для изменения сначала сохраните новую ревизию профиля через Admin.</p>}
      <label className="field">Версия сборки<input disabled={!!form.packageId} placeholder="1.0.0" value={form.version} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('version',e.target.value)} /></label>
      <label className="field">Канал<input disabled={!!form.packageId} value={form.channel} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('channel',e.target.value)} /></label>
      <div className="buttonRow"><button disabled={busy||!canPrepare||!form.profileId||!form.minecraftVersion||!form.version||!form.channel} onClick={()=>void save('build')}>Сохранить и перейти к сборке</button></div>
    </article>}
    {step==='build' && <article className="subcard"><h3>3. Сборка и файлы</h3>
      <p>Пакет: <code>{form.packageId||'ещё не создан'}</code></p>
      {draft && !dirty && !form.packageId && <BuildWorkspacePanel
        base={backendUrl} token={token} projectId={projectId} profileId={form.profileId}
        channel={form.channel} version={form.version} minecraftVersion={form.minecraftVersion}
        loader={form.loader} loaderVersion={profiles.find(p=>p.id===form.profileId)?.loaderVersion||''} javaMajor={profiles.find(p=>p.id===form.profileId)?.javaMajor||17} profileMinecraftConfigured={!!profiles.find(p=>p.id===form.profileId)?.minecraftVersion} canFileWrite={canFileWrite} releases={releases}
        onBuilt={async id=>{
          const next=await api.save({...draft,...form,packageId:id,step:'build'});
          setDraft(next);setForm(v=>({...v,packageId:id}));setDirty(false);
          await refreshDrafts();await loadChecks(id);
        }}/>}
      <button disabled={busy||!draft||dirty||!canPrepare||!!form.packageId||!form.profileId||!form.version||!form.minecraftVersion} onClick={()=>void createPackage()}>Создать пакет на Backend</button>
      {form.packageId && <><p>Статус: <strong>{packageInfo?.status||'загрузка...'}</strong></p>
        {packageInfo?.immutableBuild && <p role="status">Пакет создан из Build Workspace: состав файлов зафиксирован. Для изменения создайте новую версию.</p>}
        <label className="field">Файл<input disabled={packageInfo?.immutableBuild} type="file" onChange={(e: React.ChangeEvent<HTMLInputElement>)=>{setUploadFile(e.target.files?.[0]||null);setUploadPath(e.target.files?.[0]?.name||'');}} /></label>
        <label className="field">Путь внутри сборки<input value={uploadPath} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>setUploadPath(e.target.value)} placeholder="mods/example.jar" /></label>
        <label className="field">Ownership файла<select value={uploadOwnership} onChange={e=>setUploadOwnership(e.target.value as typeof uploadOwnership)}><option value="required">required</option><option value="managed">managed</option><option value="optional">optional (для каталога компонентов)</option></select></label>
        <button disabled={busy||!canFileWrite||!uploadFile||packageInfo?.status==='published'||packageInfo?.immutableBuild} onClick={()=>void upload()}>Загрузить с проверкой SHA-256</button>
        <h4>Файлы пакета</h4><ul>{(packageInfo?.files||[]).map(f=><li key={f.path}><code>{f.path}</code> ({f.size} байт) — {f.sha256.slice(0,16)}…</li>)}</ul>
        {!packageInfo?.files?.length&&<p className="muted">Файлы не загружены.</p>}
        {packageInfo?.manifestSchemaVersion==='3.0'&&<ComponentGraphEditor0248 key={`${form.packageId}-${catalogRefresh}`} api={api} packageId={form.packageId} canEdit={canPrepare} onChange={setCatalogBlocking}/>}
        {packageInfo?.manifestSchemaVersion!=='3.0'&&<p className="muted">Этот пакет создан с Manifest v2 и не поддерживает каталог компонентов. Для редактора создайте новый v3-пакет.</p>}
        <button disabled={busy} onClick={()=>void save('verify')}>Сохранить и перейти к проверкам</button></>}
    </article>}
    {step==='verify' && <article className="subcard"><h3>4. Проверки, подпись, runtime evidence</h3>
      {form.packageId&&packageInfo?.manifestSchemaVersion==='3.0'&&<ComponentGraphEditor0248 key={`${form.packageId}-verify-${catalogRefresh}`} api={api} packageId={form.packageId} canEdit={canPrepare} onChange={setCatalogBlocking}/>}
      <p>Реальная цепочка: validate → Ed25519 sign → stage → integrity-check → runtime evidence (при необходимости).</p>
      <div className="buttonRow">
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('validate')}>Validate</button>
        <button disabled={busy||!canPrepare||!form.packageId||catalogBlocking} onClick={()=>void packageAction('sign')}>Подписать Ed25519 (step-up)</button>
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('stage')}>Stage</button>
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('integrity-check')}>Integrity check</button>
        <button disabled={!form.packageId||busy} onClick={()=>void loadChecks(form.packageId).catch(e=>setError(printable(e)))}>Обновить результаты</button>
      </div>
      <p><strong>Integrity:</strong> {report?.integrity?.result||'не выполнено'} · Manifest: <code>{report?.integrity?.manifestDigest||'—'}</code></p>
      <p><strong>Policy:</strong> {report?.effectivePolicy?.requiredLevel||policy?.requiredLevel||'не загружена'} {report?.effectivePolicy?.source==='production-runtime-gate-0.34.11'?'· обязательная доверенная runtime-сертификация':policy?.requireServerJoin?'· требуется Server Join':''}</p>
      <p><strong>Legacy runtime v1:</strong> {report?.runtime?.filter(x=>x.result==='passed').length||0} результатов · не являются сертификацией stable</p>
      <p className="muted">Legacy smoke-test и загружаемый runtime evidence v1 не дают допуска в stable. Для stable требуется отдельная доверенная ValidationEvidence v4 от независимого аттестатора с полным покрытием targets.</p>
      {form.channel.toLowerCase() !== 'stable' && <label className="field">Signed runtime evidence (JSON-файл от CI/runtime-agent)<input disabled={busy||!canPrepare||!form.packageId||!isPassed(report)} type="file" accept="application/json,.json" onChange={(e: React.ChangeEvent<HTMLInputElement>)=>{const file=e.target.files?.[0];if(file)void submitEvidence(file);e.target.value='';}} /></label>}
      {report?.runtime?.length ? <ul>{report.runtime.map((r,i)=><li key={i}>{r.targetId}: {r.result} (actual client: {String(r.actualClient)}, server join: {String(r.serverJoin)})</li>)}</ul>:null}
      {form.packageId && <PublishReadiness0385 readiness={report?.publishReadiness} refusal={refusal} disabled={busy} refresh={()=>void loadChecks(form.packageId).catch(e=>setError(printable(e)))}/>}
      {form.packageId && <ValidationHistory03412 api={api} packageId={form.packageId}/>}
      <button disabled={busy||!draft} onClick={()=>void save('channel')}>Перейти к публикации</button>
    </article>}
    {step==='channel' && <article className="subcard"><h3>5. Канал / публикация / откат</h3>
      <p>Публикация допускается только после проверки подписи, целостности и выполнения validation policy на Backend.</p>
      <div role="status"><strong>Фактический channel head:</strong> {channelHead ? <>r{channelHead.revision} · <code>{channelHead.releaseId||'пустой канал'}</code> · {channelHead.version||'—'}</> : 'ещё не получен'} <button disabled={busy||!form.profileId} onClick={()=>void refreshChannel()}>Обновить</button>{channelHeadError && <p role="alert">Не удалось прочитать channel head: {channelHeadError}</p>}</div>
      {form.channel.toLowerCase() === 'stable' && <section aria-label="Stable runtime certification"><p><strong>Production Runtime Gate V11:</strong> {report?.effectivePolicy?.publishEligible?'Все обязательные targets подтверждены':'Публикация заблокирована до подтверждения всех обязательных targets'} · {report?.effectivePolicy?.verifiedTargets??0}/{report?.effectivePolicy?.requiredTargets??0} · policy <code>{report?.effectivePolicy?.matrixSha256||'не настроена'}</code></p>
       {Object.entries(report?.effectivePolicy?.targetBlockers??{}).length>0 && <ul>{Object.entries(report?.effectivePolicy?.targetBlockers??{}).map(([target,reason])=><li key={target}><code>{target}</code>: {reason}</li>)}</ul>}
       </section>}
      {form.packageId && <PublishReadiness0385 readiness={report?.publishReadiness} refusal={refusal} disabled={busy} refresh={()=>void loadChecks(form.packageId).catch(e=>setError(printable(e)))}/>}
      {form.packageId && <ValidationHistory03412 api={api} packageId={form.packageId}/>}
      {report?.effectivePolicy?.blockedReason && <p role="alert">{report.effectivePolicy.blockedReason}</p>}
      <div className="buttonRow"><button disabled={busy||!!pending||!canPublish||!form.packageId||dirty} onClick={()=>void validate('package-publish')}>Предпросмотр публикации</button><button disabled={busy||!!pending||!canPublish||!planned||planned.pending.intent.kind!=='package-publish'||!preview?.valid||dirty||report?.publishReadiness?.eligible!==true||(form.channel.toLowerCase()==='stable'&&!report?.effectivePolicy?.publishEligible)} onClick={()=>void execute('package-publish')}>Опубликовать</button></div>
      {preview && <div className="releaseEffect" role="status"><strong>Серверный эффект публикации</strong>{Object.entries(preview.effect).map(([key,value])=><p key={key}>{key}: {String(value)}</p>)}</div>}
      <hr/><h3>Rollback опубликованного релиза</h3>
      <label className="field">Целевая опубликованная версия<select value={targetVersion} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>{setTargetVersion(e.target.value);setRollbackPreview(null);setPlanned(null);}}><option value="">Выберите версию</option>{rollbackTargets.map(x=><option key={x.id} value={x.version}>{x.version}</option>)}</select></label>
      <div className="buttonRow"><button disabled={busy||!!pending||!canPublish||!targetVersion||dirty} onClick={()=>void validate('channel-rollback')}>Предпросмотр отката</button><button disabled={busy||!!pending||!canPublish||!planned||planned.pending.intent.kind!=='channel-rollback'||!rollbackPreview?.valid||dirty} onClick={()=>void execute('channel-rollback')}>Выполнить откат</button><button disabled={busy} onClick={()=>void api.releases(projectId).then(r=>setReleases(r.items??[])).catch(e=>setError(printable(e)))}>Обновить релизы</button></div>
      {rollbackPreview && <div className="releaseEffect" role="status"><strong>Серверный эффект отката</strong>{Object.entries(rollbackPreview.effect).map(([key,value])=><p key={key}>{key}: {String(value)}</p>)}</div>}
    </article>}
    {pending && <article className="subcard" role="status" aria-label="Контроль результата владельца">
      <h3>Проверка реального результата операции</h3>
      <p>Тип: <strong>{pending.intent.kind}</strong> · профиль <code>{pending.intent.profileId}</code> · канал <code>{pending.intent.channel}</code>.</p>
      <p>Idempotency key: <code>{pending.intent.idempotencyKey}</code> · job: <code>{pending.jobId||'ответ потерян / неизвестен'}</code></p>
      <p>{check?.message||'Проверка durable job и channel head ещё не завершена. Не создавайте повторную операцию.'}</p>
      {check?.job.lastError && <p role="alert">{check.job.lastError} · {recoveryAdvice(check.job.lastError)}</p>}
      <div className="buttonRow">
        {check?.phase==='staged' && <button disabled={busy||!canPrepare} onClick={()=>void continueStagedRollback()}>Открыть подготовленный rollback для сертификации</button>}
        {!pending.jobId && <button disabled={busy||!canPublish} onClick={()=>void recoverOperation()}>Восстановить по исходному ключу</button>}
        {pending.jobId && <a href={`#/job-monitor?job=${encodeURIComponent(pending.jobId)}`}>Открыть durable job</a>}
        {pending.jobId && <a href={auditHref(pending.jobId)}>Аудит операции</a>}
        <button disabled={busy||!check||check.phase==='waiting'} onClick={acknowledgeOperation}>Закрыть после проверки</button>
      </div>
    </article>}
    <p className="muted">Порядок владельца: сборка и компоненты → подпись/validation → просмотр эффекта → durable job → проверенный channel head → диагностика/наблюдение → rollback при необходимости. HTTP 202 не является публикацией.</p>
    <div className="buttonRow"><a href="#/diagnostics">Диагностика</a><a href="#/server-bridge">ServerBridge</a><a href="#/audit">Аудит</a></div>
    {notice && <p role="status" className="success">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {(monitorId||form.jobId) && <JobMonitor backendUrl={backendUrl} token={token} projectId={projectId} initialId={monitorId||form.jobId} canPublish={canPublish}/>}
  </section>;
}
