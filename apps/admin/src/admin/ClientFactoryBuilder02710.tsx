import {useCallback, useEffect, useMemo, useState} from 'react';

type Loader = 'vanilla'|'fabric'|'quilt'|'forge'|'neoforge';
type Config = {minecraft:string;loader:Loader;loaderVersion:string;target:string};
type Job = {id:string;workspaceId:string;state:string;createdAt:string;error?:string;files:number;planDigest?:string;request:Config};
type PlanFile = {path:string;kind?:string;sha256:string;size:number};
type Plan = {reproducibilitySha256:string;minecraftVersion:string;loader:string;loaderVersion?:string;java:{major:number};steps:Array<{id:string;adapter:string}>;sources:PlanFile[];outputs:PlanFile[];processors:unknown[]};
type Detail = {job:Job;log:string;plan?:Plan;importReport?:unknown};
type Difference={path:string;change:string;sha256?:string};
type DeliveredWorkspace = {id:string;revision:number;state:string;files:Array<{path:string;sha256:string;size:number}>};
type Envelope<T>={data:T;error?:{message:string}};
const ended=(state:string)=>['completed','failed','cancelled','interrupted'].includes(state);
const readableError=(e:unknown)=>e instanceof Error?e.message:String(e);
const key=(workspace:string)=>`neverlauncher.clientfactory.${workspace}`;
const targets=['windows/x86_64','windows/x86','linux/x86_64','linux/aarch64','darwin/x86_64','darwin/aarch64'];

export function ClientFactoryBuilder02710({backend,token,workspaceId,workspaceRevision,workspaceEmpty,onDelivered,minecraft,loader,initialLoaderVersion='',canBuild}: {
 backend:string;token:string;workspaceId:string;workspaceRevision:number;workspaceEmpty:boolean;onDelivered:(workspace:DeliveredWorkspace)=>void;minecraft:string;loader:string;initialLoaderVersion?:string;canBuild:boolean;
}) {
 const endpoint=useMemo(()=>`${backend.replace(/\/$/,'')}/api/v1/build-workspaces/${encodeURIComponent(workspaceId)}/factory/jobs`,[backend,workspaceId]);
 const [source,setSource]=useState<'version'|'modpack'>('version');
 const [modpack,setModpack]=useState<File|null>(null);
 const [configuration,setConfiguration]=useState<Config>({minecraft,loader:(loader||'vanilla') as Loader,loaderVersion:initialLoaderVersion,target:'windows/x86_64'});
 const [jobs,setJobs]=useState<Job[]>([]);
 const [current,setCurrent]=useState<string>('');
 const [detail,setDetail]=useState<Detail|null>(null);
 const [step,setStep]=useState<'configure'|'preview'|'run'|'result'>('configure');
 const [diff,setDiff]=useState<Difference[]>([]);
 const [baseJob,setBaseJob]=useState('');
 const [tab,setTab]=useState<'files'|'sources'|'processors'|'log'>('files');
 const [filter,setFilter]=useState('');
 const [busy,setBusy]=useState(false);
 const [exportBusy,setExportBusy]=useState(false);
 const [deliveryBusy,setDeliveryBusy]=useState(false);
 const [error,setError]=useState('');
 const request=useCallback(async<T,>(url:string,method:'GET'|'POST'|'DELETE'='GET',payload?:unknown,signal?:AbortSignal):Promise<T>=>{
   const response=await fetch(url,{method,headers:{Authorization:`Bearer ${token}`,...(payload===undefined?{}:{'Content-Type':'application/json'})},body:payload===undefined?undefined:JSON.stringify(payload),cache:'no-store',signal});
   const envelope=await response.json() as Envelope<T>;
   if(!response.ok)throw new Error(envelope.error?.message||`HTTP ${response.status}`);
   return envelope.data;
 },[token]);
 const refresh=useCallback(async(signal?:AbortSignal)=>{
   const history=await request<{items:Job[]}>(endpoint,'GET',undefined,signal);
   setJobs(history.items);
   return history.items;
 },[endpoint,request]);
 useEffect(()=>{
   const controller=new AbortController();
   setDetail(null);setDiff([]);setCurrent('');setStep('configure');setError('');
   refresh(controller.signal).then(items=>{
     const remembered=sessionStorage.getItem(key(workspaceId));
     if(remembered && items.some(j=>j.id===remembered))setCurrent(remembered);
     else if(items.length)setCurrent(items[0].id);
   }).catch(e=>{if(!controller.signal.aborted)setError(readableError(e))});
   return ()=>controller.abort();
 },[refresh,workspaceId]);
 useEffect(()=>{
   if(!current)return;
   const controller=new AbortController();
   sessionStorage.setItem(key(workspaceId),current);
   let timeout:number|undefined;
   const tick=async()=>{
     let terminal=false;
     try {
       const d=await request<Detail>(`${endpoint}/${encodeURIComponent(current)}`,'GET',undefined,controller.signal);
       if(controller.signal.aborted)return;
       setJobs(previous=>previous.map(j=>j.id===d.job.id?d.job:j));
       setDetail(d);setError('');
       terminal=ended(d.job.state);
       if(d.job.state==='completed')setStep('result');
       else setStep('run');
     }catch(e){if(!controller.signal.aborted)setError(readableError(e))}
     if(!controller.signal.aborted && !terminal)timeout=window.setTimeout(()=>void tick(),2500);
   };
   void tick();
   return ()=>{controller.abort();if(timeout!==undefined)window.clearTimeout(timeout)};
   // Tick follows current id, independent of the displayed polling result.
 },[endpoint,current,request,workspaceId]);
 async function act<T>(fn:()=>Promise<T>):Promise<T|undefined>{if(busy)return;setBusy(true);setError('');try{return await fn()}catch(e){setError(readableError(e));return undefined}finally{setBusy(false)}}
 const valid=configuration.minecraft.length>0 && (source==='modpack'?!!modpack:configuration.loader==='vanilla'||configuration.loaderVersion.length>0) && targets.includes(configuration.target);
 async function build(){if(!valid || !canBuild)return;await act(async()=>{
   let job:Job;
   if(source==='modpack'){
     if(!modpack)throw new Error('Выберите файл .mrpack или CurseForge ZIP');
     const body=new FormData();body.append('file',modpack);body.append('target',configuration.target);
     const result=await fetch(endpoint.replace(/\/jobs$/,'/modpack-jobs'),{method:'POST',headers:{Authorization:`Bearer ${token}`},body,cache:'no-store'});
     const response=await result.json() as Envelope<Job>;
     if(!result.ok)throw new Error(response.error?.message||`HTTP ${result.status}`);
     job=response.data;
   }else job=await request<Job>(endpoint,'POST',configuration);
   setCurrent(job.id);setDetail({job,log:''});setStep('run');setDiff([]);
   await refresh();
 });}
 async function cancel(){if(!current)return;await act(()=>request(`${endpoint}/${encodeURIComponent(current)}/cancel`,'POST',{}));}
 async function deleteJob(){if(!current||!detail||!ended(detail.job.state)||!window.confirm('Удалить завершённое задание и файлы клиента с сервера?'))return;
   await act(async()=>{await request(`${endpoint}/${encodeURIComponent(current)}`,'DELETE');setDetail(null);setCurrent('');setStep('configure');await refresh()});
 }
 async function compare(){if(!current)return;await act(async()=>{const response=await request<{items:Difference[]}>(`${endpoint}/${encodeURIComponent(current)}/diff${baseJob?`?baseJob=${encodeURIComponent(baseJob)}`:''}`);setDiff(response.items)})}
 async function deliverWorkspace(){
   if(!current||deliveryBusy||!workspaceEmpty||detail?.job.state!=='completed')return;
   setDeliveryBusy(true);setError('');
   try {
     const result=await request<DeliveredWorkspace>(`${endpoint}/${encodeURIComponent(current)}/deliver`,'POST',{revision:workspaceRevision});
     onDelivered(result);
   } catch(e){setError(readableError(e))}
   finally{setDeliveryBusy(false)}
 }
 async function exportZIP(){if(!current||exportBusy||detail?.job.state!=='completed')return;setExportBusy(true);setError('');try{
   const response=await fetch(`${endpoint}/${encodeURIComponent(current)}/export`,{headers:{Authorization:`Bearer ${token}`},cache:'no-store'});
   if(!response.ok){const data=await response.json() as Envelope<unknown>;throw new Error(data.error?.message||`HTTP ${response.status}`)}
   const objectURL=URL.createObjectURL(await response.blob());
   try{const anchor=document.createElement('a');anchor.href=objectURL;anchor.download=`neverlauncher-client-${current}.zip`;document.body.appendChild(anchor);anchor.click();anchor.remove()}
   finally{window.setTimeout(()=>URL.revokeObjectURL(objectURL),30_000)}
 }catch(e){setError(readableError(e))}finally{setExportBusy(false)}}
 const plan=detail?.plan;
 const shownFiles=useMemo(()=>((tab==='sources'?plan?.sources:plan?.outputs)||[]).filter(f=>f.path.toLowerCase().includes(filter.toLowerCase())).slice(0,350),[tab,plan,filter]);
 return <section className="subcard clientFactory" aria-label="Client Factory Builder">
   <header className="registryHeading"><div><h4>Client Factory · {__NEVERLAUNCHER_VERSION__}</h4><p className="muted">Minecraft и загрузчик → сборка → проверка SHA-256 → diff → экспорт InstallPlan и файлов.</p></div><button disabled={busy} onClick={()=>void refresh().catch(e=>setError(readableError(e)))}>Обновить задания</button></header>
   <nav className="clientFactorySteps" aria-label="Этапы Client Factory">{(['configure','preview','run','result'] as const).map((s,i)=><button type="button" key={s} aria-current={step===s?'step':undefined} disabled={s==='result'&&!plan || s==='run'&&!current} onClick={()=>setStep(s)}>{i+1}. {({configure:'Источник',preview:'План',run:'Сборка',result:'Результат'} as const)[s]}</button>)}</nav>
   {step==='configure'&&<div className="formGrid">
      <label className="field">Источник сборки<select value={source} onChange={e=>setSource(e.target.value as 'version'|'modpack')}><option value="version">Minecraft + loader</option><option value="modpack">Modrinth / CurseForge modpack</option></select></label>
      <label className="field">Minecraft (закреплён за профилем)<input value={configuration.minecraft} readOnly/></label>
      <label className="field">Загрузчик (закреплён за профилем)<input value={configuration.loader} readOnly/></label>
      {source==='version'&&configuration.loader!=='vanilla'&&<label className="field">Точная версия загрузчика<input value={configuration.loaderVersion} onChange={e=>setConfiguration(v=>({...v,loaderVersion:e.target.value.trim()}))} placeholder="Введите точную версию, не latest"/></label>}
      <label className="field">Целевая ОС и архитектура<select value={configuration.target} onChange={e=>setConfiguration(v=>({...v,target:e.target.value}))}>{targets.map(t=><option key={t} value={t}>{t}</option>)}</select></label>
      {source==='modpack'&&<label className="field">Архив сборки (.mrpack / .zip)<input type="file" accept=".mrpack,.zip" onChange={e=>setModpack(e.target.files?.[0]||null)} /></label>}
      <p className="muted">Импорт исходной папки и ручной выбор файлов доступны в Build Workspace ниже. Client Factory использует реальные Vanilla/Fabric/Quilt/Forge/NeoForge materializers.</p>
      <button disabled={!valid} onClick={()=>setStep('preview')}>Предварительный план</button>
   </div>}
   {step==='preview'&&<>
     <h5>Предварительный план установки</h5>
     <dl className="clientFactoryMeta"><dt>Источник</dt><dd>{source==='modpack'?`Modpack ${modpack?.name||''}`:`Minecraft ${configuration.minecraft}`}</dd><dt>Загрузчик профиля</dt><dd>{configuration.loader} {configuration.loader!=='vanilla'&&configuration.loaderVersion}</dd><dt>Target</dt><dd>{configuration.target}</dd><dt>Этапы</dt><dd>Resolution → Downloads → Processors → SHA-256 verification</dd></dl>
     <p className="muted">Точный InstallPlan, список библиотек, natives, Java и hashes вычисляются materializer во время установки и доступны после верификации. Пока это предварительный план параметров, а не подтверждённый lockfile.</p>
     <div className="buttonRow"><button onClick={()=>setStep('configure')}>Изменить</button><button disabled={busy||!canBuild} onClick={()=>void build()}>Создать сборку</button></div>
   </>}
   {jobs.length>0&&<label className="field">История заданий (сохраняется на сервере)<select value={current} onChange={e=>{setCurrent(e.target.value);setDetail(null);setDiff([]);setStep('run')}}><option value="">Выберите задание</option>{jobs.map(j=><option key={j.id} value={j.id}>{new Date(j.createdAt).toLocaleString()} · {j.request.loader} · {j.state} · {j.id.slice(0,8)}</option>)}</select></label>}
   {current&&detail&&(step==='run'||step==='result')&&<>
      <p>Задание <code>{current}</code> · <strong>{detail.job.state}</strong> · {detail.job.files} файлов</p>
      {!ended(detail.job.state)&&<div className="buttonRow"><span role="status">Worker выполняет build или verify; журнал обновляется автоматически.</span><button disabled={busy} onClick={()=>void cancel()}>Отменить</button></div>}
      {detail.job.error&&<p role="alert" className="error">{detail.job.error}</p>}
      {detail.importReport&&detail.job.state!=='completed'&&<pre className="clientFactoryLog">{JSON.stringify(detail.importReport,null,2)}</pre>}
      {ended(detail.job.state)&&detail.job.state!=='interrupted'&&<button disabled={busy} onClick={()=>void deleteJob()}>Удалить завершённое задание</button>}
      {step==='run'&&<><h5>Processor / installer logs</h5><pre className="clientFactoryLog" aria-label="Журнал Client Factory">{detail.log||'Нет сообщений; проверьте состояние задания.'}</pre></>}
      {plan&&step==='result'&&<>
        <dl className="clientFactoryMeta"><dt>InstallPlan</dt><dd><code>{plan.reproducibilitySha256}</code></dd><dt>Minecraft</dt><dd>{plan.minecraftVersion}</dd><dt>Loader</dt><dd>{plan.loader} {plan.loaderVersion||''}</dd><dt>Java</dt><dd>{plan.java.major}</dd><dt>Files</dt><dd>{plan.outputs.length}</dd><dt>Processors</dt><dd>{plan.processors.length}</dd></dl>
        <div className="buttonRow"><button disabled={!canBuild||!workspaceEmpty||deliveryBusy} onClick={()=>void deliverWorkspace()}>{deliveryBusy?'Верификация и перенос…':'Перенести сборку в Build Workspace'}</button><button disabled={exportBusy} onClick={()=>void exportZIP()}>{exportBusy?'Проверка и упаковка…':'Локальный экспорт (ZIP)'}</button><button onClick={()=>{setStep('run');setTab('log')}}>Журнал</button></div>
        {!workspaceEmpty&&<p className="muted">Прямой перенос доступен только для пустого workspace до stage. Для нового запуска создайте пустой workspace с необходимой Java.</p>}
        <div className="buttonRow"><label className="field">Сравнение с заданием<select value={baseJob} onChange={e=>setBaseJob(e.target.value)}><option value="">Нет (все файлы как новые)</option>{jobs.filter(j=>j.state==='completed'&&j.id!==current).map(j=><option value={j.id} key={j.id}>{j.id.slice(0,8)} · {j.request.minecraft}</option>)}</select></label><button disabled={busy} onClick={()=>void compare()}>Показать diff</button></div>
        {!!diff.length&&<div className="clientFactoryFileList" aria-label="Изменённые файлы"><h5>Diff ({diff.length})</h5>{diff.slice(0,350).map(f=><div key={f.path}><code>{f.path}</code> — {f.change}</div>)}</div>}
        <div className="buttonRow">{(['files','sources','processors','log'] as const).map(name=><button type="button" aria-pressed={tab===name} key={name} onClick={()=>setTab(name)}>{({files:'Outputs',sources:'Sources',processors:'Processors',log:'Logs'} as const)[name]}</button>)}</div>
        {(tab==='files'||tab==='sources')&&<><label className="field">Поиск файла<input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="libraries/…"/></label><div className="clientFactoryFileList">{shownFiles.map(f=><div key={f.path}><code>{f.path}</code> · {f.size} B · <code>{f.sha256.slice(0,16)}…</code></div>)}<p className="muted">Показаны первые 350 совпадений из {tab==='files'?plan.outputs.length:plan.sources.length}.</p></div></>}
        {tab==='processors'&&<pre className="clientFactoryLog">{JSON.stringify(plan.processors,null,2)}</pre>}
        {tab==='log'&&<pre className="clientFactoryLog">{detail.log}</pre>}
        {detail.importReport&&<pre className="clientFactoryLog">{JSON.stringify(detail.importReport,null,2)}</pre>}
        <p className="muted">Серверный перенос проверяет исходные байты, шифрует их и связывает runtime.launch с точным профилем загрузчика. После переноса выполните Stage → Validate → Build → Sign → Staged Run → Publish. Успешный перенос не удостоверяет реальный запуск Minecraft.</p>
      </>}
   </>}
   {error&&<p role="alert" className="error">{error}</p>}
 </section>;
}
