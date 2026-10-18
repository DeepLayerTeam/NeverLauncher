import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ReleaseApi, type Draft, type DraftFields, type PackageInfo, type Preview, type ValidationReport } from '../api/release';
import { JobMonitor } from './JobMonitor';

type Step = 'project'|'profile'|'build'|'verify'|'channel';
const steps: Array<{id: Step; title:string}> = [
  {id:'project',title:'Проект'}, {id:'profile',title:'Профиль и загрузчик'}, {id:'build',title:'Сборка и файлы'}, {id:'verify',title:'Проверка и подпись'}, {id:'channel',title:'Публикация и откат'},
];
const empty = (projectId:string): DraftFields => ({projectId,profileId:'',channel:'stable',version:'',minecraftVersion:'',loader:'vanilla',packageId:'',jobId:'',step:'project'});
const printable = (e:unknown) => e instanceof Error ? e.message : String(e);
const isPassed = (v: ValidationReport | null) => v?.integrity?.result === 'passed';

export function ReleaseWorkspace({backendUrl,token,projectId,canPrepare,canFileWrite,canPublish}: {backendUrl:string;token:string;projectId:string;canPrepare:boolean;canFileWrite:boolean;canPublish:boolean}) {
  const api = useMemo(() => new ReleaseApi(backendUrl,token),[backendUrl,token]);
  const [drafts,setDrafts] = useState<Draft[]>([]);
  const [draft,setDraft] = useState<Draft|null>(null);
  const [form,setForm] = useState<DraftFields>(empty(projectId));
  const [step,setStep] = useState<Step>('project');
  const [profiles,setProfiles] = useState<Array<{id:string;name:string;loader:string}>>([]);
  const [releases,setReleases] = useState<Array<{id:string;version:string;profileId:string;channel:string;status:string}>>([]);
  const [packageInfo,setPackageInfo] = useState<PackageInfo|null>(null);
  const [report,setReport] = useState<ValidationReport|null>(null);
  const [policy,setPolicy] = useState<ValidationReport['policy']|null>(null);
  const [preview,setPreview] = useState<Preview|null>(null);
  const [rollbackPreview,setRollbackPreview] = useState<Preview|null>(null);
  const [targetVersion,setTargetVersion] = useState('');
  const [monitorId,setMonitorId] = useState('');
  const [uploadFile,setUploadFile] = useState<File|null>(null);
  const [uploadPath,setUploadPath] = useState('');
  const [busy,setBusy] = useState(false);
  const [notice,setNotice] = useState('');
  const [error,setError] = useState('');
  const [dirty,setDirty] = useState(false);
  const refreshDrafts = useCallback(async () => { const items = await api.drafts(projectId); setDrafts(items.items ?? []); },[api,projectId]);
  const loadChecks = useCallback(async (id:string) => {
    const [info,checks] = await Promise.all([api.package(id),api.validations(id)]);
    setPackageInfo(info);setReport(checks);
  },[api]);
  useEffect(() => {
    let live=true;
    setDraft(null);setForm(empty(projectId));setDrafts([]);setStep('project');setPackageInfo(null);setReport(null);setPreview(null);setRollbackPreview(null);setMonitorId('');setDirty(false);
    if (!projectId || !canPrepare) return;
    Promise.all([api.drafts(projectId),api.profiles(projectId),api.releases(projectId),api.policy(projectId)])
      .then(([ds,ps,vs,p])=>{if(live){setDrafts(ds.items??[]);setProfiles(ps.items??[]);setReleases(vs.items??[]);setPolicy(p);}})
      .catch(e=>{if(live)setError(printable(e));});
    return ()=>{live=false};
  },[api,projectId,canPrepare]);
  function edit(key:keyof DraftFields,value:string) {
    if (form.packageId && ['profileId','channel','version','loader','minecraftVersion'].includes(key)) { setError('Поля сборки закреплены за созданным пакетом. Для изменения создайте новый черновик.');return; }
    setForm(v=>({...v,[key]:value}));setDirty(true);setPreview(null);setRollbackPreview(null);setError('');
  }
  async function perform<T>(action:()=>Promise<T>,success:string):Promise<T|undefined> {
    if (busy) return;
    setBusy(true);setError('');setNotice('');
    try { const result=await action();setNotice(success);return result; }
    catch(e){setError(printable(e));return undefined;}
    finally{setBusy(false)}
  }
  function loadDraft(d:Draft){
    if (dirty && !window.confirm('Несохранённые изменения будут потеряны. Продолжить?')) return;
    setDraft(d);setForm({projectId:d.projectId,profileId:d.profileId,channel:d.channel,version:d.version,minecraftVersion:d.minecraftVersion,loader:d.loader,packageId:d.packageId,jobId:d.jobId,step:d.step});
    setStep(steps.some(s=>s.id===d.step)?d.step as Step:'project');setMonitorId(d.jobId);
    if(d.packageId && !d.jobId)void api.linkedJob(d.id).then(job=>setMonitorId(job.id)).catch(()=>undefined);
    setDirty(false);setPreview(null);setRollbackPreview(null);
    setPackageInfo(null);setReport(null);setTargetVersion('');
    if(d.packageId) void loadChecks(d.packageId).catch(e=>setError(printable(e)));
  }
  async function save(nextStep?:Step): Promise<Draft|undefined> {
    const fields={...form,step:nextStep||step};
    const updated=await perform(async()=>draft ? api.save({...draft,...fields}) : api.create(fields),'Черновик сохранён на Backend.');
    if(updated){setDraft(updated);setForm(fields);setStep(fields.step as Step);setDirty(false);await refreshDrafts();}
    return updated;
  }
  async function removeDraft(){if(!draft || !window.confirm('Удалить сохранённый черновик? Пакет и задание при этом НЕ удаляются.'))return;
    const done=await perform(()=>api.remove(draft.id),'Черновик удалён.');if(done){setDraft(null);setForm(empty(projectId));setStep('project');setPackageInfo(null);setReport(null);setMonitorId('');setDirty(false);await refreshDrafts();}
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
    const result=await perform(()=>api.upload(form.packageId,uploadFile,uploadPath||uploadFile.name),'Файл загружен и SHA-256 проверен Backend.');
    if(result){setUploadFile(null);setUploadPath('');await loadChecks(form.packageId).catch(e=>setError(printable(e)));}
  }
  async function packageAction(action:'validate'|'sign'|'stage'|'integrity-check'){
    if(!form.packageId)return;
    await perform(async()=>{const result=await api.packageAction<Record<string,unknown>>(form.packageId,action);await loadChecks(form.packageId);return result;},`${action}: ответ Backend получен.`);
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
  const operation=(kind:'package-publish'|'channel-rollback',toVersion='')=>({kind,projectId,resourceId:kind==='package-publish'?form.packageId:undefined,profileId:form.profileId,channel:form.channel,toVersion:kind==='channel-rollback'?toVersion:undefined,
    idempotencyKey:kind==='package-publish'?`release-workspace-${draft?.id||''}`:`release-workspace-${draft?.id||''}-rollback-${toVersion}`});
  async function validate(kind:'package-publish'|'channel-rollback'){
    const next=await perform(()=>api.validateOperation(operation(kind,targetVersion)), 'Backend проверил полномочия, policy и точный эффект операции.');
    if(kind==='package-publish')setPreview(next||null);else setRollbackPreview(next||null);
  }
  async function execute(kind:'package-publish'|'channel-rollback'){
    const previewValue=kind==='package-publish'?preview:rollbackPreview;
    if(!previewValue?.valid || !draft || dirty)return;
    const effect=Object.entries(previewValue.effect||{}).map(([k,v])=>`${k}: ${v}`).join('\n');
    if(!window.confirm(`Подтвердите ${kind} в проекте ${projectId}:\n${effect}`))return;
    const job=await perform(()=>api.executeOperation(operation(kind,targetVersion)),'Операция принята Backend, её ход виден в Job monitor.');
    if(!job)return;
    setMonitorId(job.id);
    if(kind==='package-publish'){
      const saved=await perform(()=>api.save({...draft,...form,step:'channel',jobId:job.id}),'Job ID сохранён в черновике.');
      if(saved){setDraft(saved);setForm(v=>({...v,step:'channel',jobId:job.id}));setDirty(false);await refreshDrafts();}
    }
    setPreview(null);setRollbackPreview(null);
  }
  const rollbackTargets=releases.filter(v=>v.status==='published' && v.profileId===form.profileId && v.channel===form.channel);
  return <section className="card wide releaseWorkspace">
    <h2>Release Workspace · 0.21.8</h2>
    <p className="muted">Мастер: проект → профиль и загрузчик → сборка → проверка → канал. Черновики хранятся на Backend с проверкой версии при сохранении.</p>
    <div className="formGrid"><article className="subcard">
      <h3>Черновики проекта {projectId || '—'}</h3>
      <div className="buttonRow"><button disabled={busy || !canPrepare} onClick={()=>{if(dirty && !window.confirm('Отменить несохранённые изменения?'))return;setDraft(null);setForm(empty(projectId));setStep('project');setPackageInfo(null);setReport(null);setMonitorId('');setDirty(false);}}>Новый черновик</button><button disabled={busy} onClick={()=>void refreshDrafts().catch(e=>setError(printable(e)))}>Обновить</button></div>
      <ul className="releaseDraftList">{drafts.map(d=><li key={d.id}><button aria-current={draft?.id===d.id?'page':undefined} onClick={()=>loadDraft(d)}>{d.version || 'Без версии'} · {d.profileId || 'Без профиля'} · {d.step} <small>({new Date(d.updatedAt).toLocaleString()})</small></button></li>)}</ul>
      {drafts.length===0 && <p className="muted">Черновиков нет. Укажите параметры и сохраните новый.</p>}
      {draft && <p>Черновик: <code>{draft.id}</code> · revision {draft.revision}</p>}
      <div className="buttonRow"><button disabled={busy||!canPrepare} onClick={()=>void save()}>Сохранить {dirty?'изменения':'черновик'}</button><button disabled={!draft||busy} className="danger" onClick={()=>void removeDraft()}>Удалить черновик</button></div>
    </article><article className="subcard"><h3>Этапы выпуска</h3><nav className="releaseSteps" aria-label="Этапы выпуска">{steps.map(item=><button key={item.id} type="button" aria-current={step===item.id?'step':undefined} onClick={()=>{setStep(item.id);setPreview(null);setRollbackPreview(null);}}>{item.title}</button>)}</nav><p>{dirty?'Есть несохранённые изменения.':'Данные синхронизированы с последним сохранением.'}</p></article></div>
    {step==='project' && <article className="subcard"><h3>1. Проект</h3><p>Выбранный проект: <strong>{projectId}</strong>. Переключение выполняется в верхней панели Admin. Черновики доступны только своему владельцу с правом release:prepare.</p><button disabled={busy||!projectId||!canPrepare} onClick={()=>void save('profile')}>Сохранить и перейти к профилю</button></article>}
    {step==='profile' && <article className="subcard"><h3>2. Профиль / загрузчик / Minecraft</h3>
      <label className="field">Профиль<select disabled={!!form.packageId} value={form.profileId} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>{const found=profiles.find(p=>p.id===e.target.value);setForm(v=>({...v,profileId:e.target.value,loader:found?.loader||v.loader}));setDirty(true);}}><option value="">Выберите профиль</option>{profiles.map(p=><option key={p.id} value={p.id}>{p.name||p.id} ({p.id})</option>)}</select></label>
      <label className="field">Загрузчик<select disabled={!!form.packageId} value={form.loader} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>edit('loader',e.target.value)}>{['vanilla','fabric','quilt','forge','neoforge'].map(x=><option key={x} value={x}>{x}</option>)}</select></label>
      <label className="field">Версия Minecraft<input disabled={!!form.packageId} placeholder="1.21.1" value={form.minecraftVersion} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('minecraftVersion',e.target.value)} /></label>
      <label className="field">Версия сборки<input disabled={!!form.packageId} placeholder="1.0.0" value={form.version} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('version',e.target.value)} /></label>
      <label className="field">Канал<input disabled={!!form.packageId} value={form.channel} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>edit('channel',e.target.value)} /></label>
      <div className="buttonRow"><button disabled={busy||!canPrepare||!form.profileId||!form.minecraftVersion||!form.version||!form.channel} onClick={()=>void save('build')}>Сохранить и перейти к сборке</button></div>
    </article>}
    {step==='build' && <article className="subcard"><h3>3. Сборка и файлы</h3>
      <p>Пакет: <code>{form.packageId||'ещё не создан'}</code></p>
      <button disabled={busy||!draft||dirty||!canPrepare||!!form.packageId||!form.profileId||!form.version||!form.minecraftVersion} onClick={()=>void createPackage()}>Создать пакет на Backend</button>
      {form.packageId && <><p>Статус: <strong>{packageInfo?.status||'загрузка...'}</strong></p>
        <label className="field">Файл<input type="file" onChange={(e: React.ChangeEvent<HTMLInputElement>)=>{setUploadFile(e.target.files?.[0]||null);setUploadPath(e.target.files?.[0]?.name||'');}} /></label>
        <label className="field">Путь внутри сборки<input value={uploadPath} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>setUploadPath(e.target.value)} placeholder="mods/example.jar" /></label>
        <button disabled={busy||!canFileWrite||!uploadFile||packageInfo?.status==='published'} onClick={()=>void upload()}>Загрузить с проверкой SHA-256</button>
        <h4>Файлы пакета</h4><ul>{(packageInfo?.files||[]).map(f=><li key={f.path}><code>{f.path}</code> ({f.size} байт) — {f.sha256.slice(0,16)}…</li>)}</ul>
        {!packageInfo?.files?.length&&<p className="muted">Файлы не загружены.</p>}
        <button disabled={busy} onClick={()=>void save('verify')}>Сохранить и перейти к проверкам</button></>}
    </article>}
    {step==='verify' && <article className="subcard"><h3>4. Проверки, подпись, runtime evidence</h3>
      <p>Реальная цепочка: validate → Ed25519 sign → stage → integrity-check → runtime evidence (при необходимости).</p>
      <div className="buttonRow">
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('validate')}>Validate</button>
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('sign')}>Подписать Ed25519 (step-up)</button>
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('stage')}>Stage</button>
        <button disabled={busy||!canPrepare||!form.packageId} onClick={()=>void packageAction('integrity-check')}>Integrity check</button>
        <button disabled={!form.packageId||busy} onClick={()=>void loadChecks(form.packageId).catch(e=>setError(printable(e)))}>Обновить результаты</button>
      </div>
      <p><strong>Integrity:</strong> {report?.integrity?.result||'не выполнено'} · Manifest: <code>{report?.integrity?.manifestDigest||'—'}</code></p>
      <p><strong>Policy:</strong> {policy?.requiredLevel||'не загружена'} {policy?.requireServerJoin?'· требуется Server Join':''}</p>
      <p><strong>Runtime:</strong> {report?.runtime?.filter(x=>x.result==='passed').length||0} подтверждённых запусков</p>
      <p className="muted">Legacy smoke-test не запускает Minecraft; его результат не считается runtime evidence. Загрузите подписанный CI/runtime-agent документ с результатом фактического запуска.</p>
      <label className="field">Signed runtime evidence (JSON-файл от CI/runtime-agent)<input disabled={busy||!canPrepare||!form.packageId||!isPassed(report)} type="file" accept="application/json,.json" onChange={(e: React.ChangeEvent<HTMLInputElement>)=>{const file=e.target.files?.[0];if(file)void submitEvidence(file);e.target.value='';}} /></label>
      {report?.runtime?.length ? <ul>{report.runtime.map((r,i)=><li key={i}>{r.targetId}: {r.result} (actual client: {String(r.actualClient)}, server join: {String(r.serverJoin)})</li>)}</ul>:null}
      <button disabled={busy||!draft} onClick={()=>void save('channel')}>Перейти к публикации</button>
    </article>}
    {step==='channel' && <article className="subcard"><h3>5. Канал / публикация / откат</h3>
      <p>Публикация допускается только после проверки подписи, целостности и выполнения validation policy на Backend.</p>
      <div className="buttonRow"><button disabled={busy||!canPublish||!form.packageId||dirty} onClick={()=>void validate('package-publish')}>Предпросмотр публикации</button><button disabled={busy||!canPublish||!preview?.valid||dirty} onClick={()=>void execute('package-publish')}>Опубликовать</button></div>
      {preview && <div className="releaseEffect" role="status"><strong>Серверный эффект публикации</strong>{Object.entries(preview.effect).map(([key,value])=><p key={key}>{key}: {String(value)}</p>)}</div>}
      <hr/><h3>Rollback опубликованного релиза</h3>
      <label className="field">Целевая опубликованная версия<select value={targetVersion} onChange={(e: React.ChangeEvent<HTMLSelectElement>)=>{setTargetVersion(e.target.value);setRollbackPreview(null);}}><option value="">Выберите версию</option>{rollbackTargets.map(x=><option key={x.id} value={x.version}>{x.version}</option>)}</select></label>
      <div className="buttonRow"><button disabled={busy||!canPublish||!targetVersion||dirty} onClick={()=>void validate('channel-rollback')}>Предпросмотр отката</button><button disabled={busy||!canPublish||!rollbackPreview?.valid||dirty} onClick={()=>void execute('channel-rollback')}>Выполнить откат</button><button disabled={busy} onClick={()=>void api.releases(projectId).then(r=>setReleases(r.items??[])).catch(e=>setError(printable(e)))}>Обновить релизы</button></div>
      {rollbackPreview && <div className="releaseEffect" role="status"><strong>Серверный эффект отката</strong>{Object.entries(rollbackPreview.effect).map(([key,value])=><p key={key}>{key}: {String(value)}</p>)}</div>}
    </article>}
    {notice && <p role="status" className="success">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {(monitorId||form.jobId) && <JobMonitor backendUrl={backendUrl} token={token} projectId={projectId} initialId={monitorId||form.jobId} canPublish={canPublish}/>}
  </section>;
}
