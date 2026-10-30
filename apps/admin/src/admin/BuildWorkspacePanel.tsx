import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {ClientFactoryBuilder02710} from './ClientFactoryBuilder02710';
import {diffCounts0384,hasCompleteBuild0384,planImports0384,type FileDifference0384} from './build-files-0384';

interface BuildFile {path:string;size:number;sha256:string;ownership:string;executable:boolean;selected:boolean}
interface Settings {
 minecraft:{version:string;loader:string;loaderVersion?:string;mainClass?:string;gameArgs?:string[]};
 runtime:{java:{majorVersion:number;minimumMajorVersion?:number;recommendedMajorVersion?:number;maximumMajorVersion?:number;distribution:string};memory?:{minimumMb:number;recommendedMb:number;maximumMb:number};jvmArgs?:string[];launch?:{mainClass?:string;classpathEntries?:string[];classpathStrategy?:string}};
 toolVersions?:Record<string,string>;
}
interface BuildWorkspace {
 id:string;projectId:string;profileId:string;channel:string;version:string;state:string;revision:number;
 profileRevision:number;profileDigest:string;files:BuildFile[];settings:Settings;buildDigest?:string;packageId?:string;
}
type Wrapped<T>={data:T;error?:{message?:string}};
type Scan0384={revision:number;status:string;files:Array<{path:string;sha256:string;size:number;status:string}>};
type Validation0384={valid:boolean;buildDigest:string;fileCount:number;profileRevision:number};
type Diff0384={revision:number;items:FileDifference0384[]};
const message=(e:unknown)=>e instanceof Error?e.message:String(e);

export function BuildWorkspacePanel({base,token,projectId,profileId,channel,version,minecraftVersion,loader,loaderVersion='',javaMajor:profileJavaMajor=17,profileMinecraftConfigured=false,canFileWrite,onBuilt,releases}: {
 base:string;token:string;projectId:string;profileId:string;channel:string;version:string;minecraftVersion:string;loader:string;loaderVersion?:string;javaMajor?:number;profileMinecraftConfigured?:boolean;
 canFileWrite:boolean;onBuilt:(id:string)=>Promise<void>;releases:Array<{id:string;version:string;profileId:string;channel:string;status:string}>;
}){
 const [items,setItems]=useState<BuildWorkspace[]>([]);
 const [workspace,setWorkspace]=useState<BuildWorkspace|null>(null);
 const [javaMajor,setJavaMajor]=useState(profileJavaMajor);
 useEffect(()=>{setJavaMajor(profileJavaMajor)},[profileJavaMajor,profileId]);
 const [ram,setRam]=useState(4096);
 const [settingsJSON,setSettingsJSON]=useState('');
 const [selected,setSelected]=useState<string[]>([]);
 const [ownership,setOwnership]=useState<'required'|'managed'|'optional'>('required');
 const [baseVersionId,setBaseVersionId]=useState('');
 const [comparison,setComparison]=useState<Diff0384|null>(null);
 const [scan,setScan]=useState<Scan0384|null>(null);
 const [validation,setValidation]=useState<Validation0384|null>(null);
 const [progress,setProgress]=useState('');
 const [filter,setFilter]=useState('');
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [materialized,setMaterialized]=useState<boolean|null>(null);
 const endpoint=useMemo(()=>base.replace(/\/$/,''),[base]);
 const api=useCallback(async<T,>(url:string,method:'GET'|'POST'|'DELETE'='GET',payload?:unknown):Promise<T>=>{
   const res=await fetch(`${endpoint}${url}`,{method,headers:{Authorization:`Bearer ${token}`,...(payload===undefined?{}:{'Content-Type':'application/json'})},body:payload===undefined?undefined:JSON.stringify(payload),cache:'no-store'});
   const reply=await res.json() as Wrapped<T>;
   if(!res.ok)throw new Error(reply.error?.message||`HTTP ${res.status}`);
   return reply.data;
 },[endpoint,token]);
 const refresh=useCallback(async()=>{
   if(!projectId)return;
   const response=await api<{items:BuildWorkspace[]}>(`/api/v1/build-workspaces?projectId=${encodeURIComponent(projectId)}`);
   const matches=response.items.filter(x=>x.profileId===profileId&&x.channel===channel&&x.version===version);
   setItems(matches);
 },[api,projectId,profileId,channel,version]);
 useEffect(()=>{setWorkspace(null);setScan(null);setComparison(null);setValidation(null);setSelected([]);setError('');setProgress('');setMaterialized(null);void refresh().catch(e=>setError(message(e)))},[refresh]);
 const load=useCallback((ws:BuildWorkspace)=>{setWorkspace(ws);setSelected(ws.files.filter(f=>f.selected).map(f=>f.path));setScan(null);setValidation(null);setComparison(null);setMaterialized(null)},[]);
 async function run<T>(fn:()=>Promise<T>):Promise<T|undefined>{if(busy)return;setBusy(true);setError('');try{return await fn()}catch(e){setError(message(e));return undefined}finally{setBusy(false)}}
 async function create(){
   await run(async()=>{
     const settings:Settings=settingsJSON.trim()?JSON.parse(settingsJSON) as Settings:{minecraft:{version:minecraftVersion,loader,...(loaderVersion?{loaderVersion}:{})},runtime:{java:{majorVersion:javaMajor,distribution:'any'},memory:{minimumMb:512,recommendedMb:ram,maximumMb:Math.max(ram,8192)}}};
     if(!settings.minecraft?.version||!settings.runtime?.java?.majorVersion)throw new Error('Укажите Minecraft и Java в параметрах сборки');
     const ws=await api<BuildWorkspace>('/api/v1/build-workspaces','POST',{projectId,profileId,channel,version,settings});load(ws);await refresh();
   });
 }
 async function importFiles(files:FileList|null){
   if(!workspace||!files?.length)return;
   await run(async()=>{
     const {accepted,skipped}=planImports0384(Array.from(files));
     if(!accepted.length){setProgress(`Нет файлов для импорта; защищённых пользовательских файлов пропущено ${skipped.length}.`);return}
     let current=workspace;let uploaded=0;
     try{
       for(const {file,path} of accepted){
         const body=new FormData();body.append('file',file);body.append('path',path);body.append('revision',String(current.revision));body.append('ownership',ownership);
         setProgress(`Импорт ${uploaded+1}/${accepted.length}: ${path}`);
         const res=await fetch(`${endpoint}/api/v1/build-workspaces/${encodeURIComponent(current.id)}/files`,{method:'POST',headers:{Authorization:`Bearer ${token}`},body,cache:'no-store'});
         const reply=await res.json() as Wrapped<BuildWorkspace>;
         if(!res.ok)throw new Error(`${path}: ${reply.error?.message||`HTTP ${res.status}`}`);
         current=reply.data;uploaded++;load(current);
       }
       setProgress(`Загружено ${uploaded}/${accepted.length}; защищённых пользовательских файлов пропущено ${skipped.length}.`);
     }catch(e){
       // A lost response may still have committed bytes. Never retry blindly:
       // re-read the server revision and let the operator inspect the result.
       try{current=await api<BuildWorkspace>(`/api/v1/build-workspaces/${encodeURIComponent(current.id)}`);load(current)}catch{/* preserve last confirmed revision */}
       setProgress(`Подтверждено ${uploaded}/${accepted.length}. Состояние перечитано из Backend.`);
       throw e;
     }finally{await refresh()}
   });
 }
 async function removeFile(path:string){
   if(!workspace||workspace.state==='built'||!canFileWrite||!window.confirm(`Удалить ${path} из подготовляемой сборки?`))return;
   await run(async()=>{
     const ws=await api<BuildWorkspace>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/files`,'DELETE',{revision:workspace.revision,path});
     load(ws);setProgress(`Файл ${path} исключён из рабочего набора.`);await refresh();
   });
 }
 async function scanFiles(){if(!workspace)return;await run(async()=>setScan(await api<Scan0384>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/scan`)))}
 async function diff(){if(!workspace)return;await run(async()=>setComparison(await api<Diff0384>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/diff${baseVersionId?`?baseVersionId=${encodeURIComponent(baseVersionId)}`:''}`)))}
 async function stage(){if(!workspace)return;await run(async()=>{
   const ws=await api<BuildWorkspace>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/stage`,'POST',{revision:workspace.revision,paths:selected});load(ws);
 })}
 async function validate(){if(!workspace)return;await run(async()=>setValidation(await api<Validation0384>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/validate`)))}
 async function verifyPackage(ws:BuildWorkspace){
   if(!ws.packageId)throw new Error('Backend did not return an immutable package ID');
   const pkg=await api<{packageId:string;projectId:string;profileId:string;channel:string;version:string;files:Array<{path:string;sha256:string;size:number}>}>(`/api/v1/packages/${encodeURIComponent(ws.packageId)}`);
   const complete=pkg.packageId===ws.packageId&&pkg.projectId===projectId&&pkg.profileId===profileId&&pkg.channel===channel&&pkg.version===version&&hasCompleteBuild0384(ws.files,pkg.files);
   setMaterialized(complete);
   if(!complete)throw new Error('Материализованный пакет не совпадает с выбранными исходными файлами. Привязка к релизу остановлена.');
 }
 async function build(){if(!workspace)return;await run(async()=>{
   const ws=await api<BuildWorkspace>(`/api/v1/build-workspaces/${encodeURIComponent(workspace.id)}/build`,'POST',{revision:workspace.revision});load(ws);
   await verifyPackage(ws);
   await onBuilt(ws.packageId!);
 })}
 const shown=workspace?.files.filter(f=>f.path.toLocaleLowerCase().includes(filter.toLocaleLowerCase()))??[];
 const counts=comparison?diffCounts0384(comparison.items):{};
 return <article className="subcard">
   <h4>Build Workspace · {__NEVERLAUNCHER_VERSION__}</h4>
   <p className="muted">Каталог или отдельные файлы → SHA-256 → сравнение → выбор stage → validate → проверка материализованного пакета. Публикация и подпись остаются в Release Workspace.</p>
   {!workspace&&<>
     <label className="field">Java major <input type="number" min={8} max={255} disabled={!!profileMinecraftConfigured} value={javaMajor} onChange={e=>setJavaMajor(Number(e.target.value))}/></label>
     <label className="field">RAM recommended (MB) <input type="number" min={512} max={131072} value={ram} onChange={e=>setRam(Number(e.target.value))}/></label>
     <label className="field">Дополнительные настройки сборки (JSON, необязательно)<textarea rows={3} value={settingsJSON} onChange={e=>setSettingsJSON(e.target.value)} placeholder="minecraft, runtime, fileRules, toolVersions"/></label>
     <button disabled={busy||!version||!profileId||!minecraftVersion||!canFileWrite} onClick={()=>void create()}>Создать workspace</button>
     {items.length>0&&<><h5>Продолжить workspace</h5><ul>{items.map(x=><li key={x.id}><button disabled={busy} onClick={()=>load(x)}>{x.id} · {x.state} · r{x.revision} · {x.files.length} файлов</button></li>)}</ul></>}
   </>}
   {workspace&&<>
     <ClientFactoryBuilder02710 backend={base} token={token} workspaceId={workspace.id} workspaceRevision={workspace.revision} workspaceEmpty={workspace.files.length===0 && workspace.state==='importing'} onDelivered={ws=>{void api<BuildWorkspace>(`/api/v1/build-workspaces/${encodeURIComponent(ws.id)}`).then(updated=>{load(updated);setProgress(`Client Factory: ${updated.files.length} проверенных файлов перенесено в Build Workspace; выполните stage, validate, build и игровую приёмку.`);return refresh()}).catch(e=>setError(message(e)))}} minecraft={workspace.settings.minecraft.version} loader={workspace.settings.minecraft.loader} initialLoaderVersion={workspace.settings.minecraft.loaderVersion||loaderVersion} canBuild={canFileWrite && workspace.state!=='built'} />
     <p>Workspace: <code>{workspace.id}</code> · {workspace.state} · revision {workspace.revision} · Profile revision {workspace.profileRevision}</p>
     <div className="buttonRow"><button disabled={busy} onClick={()=>{setWorkspace(null);void refresh()}}>Другой workspace</button><button disabled={busy} onClick={()=>void scanFiles()}>Scan / SHA-256</button></div>
     {workspace.state!=='built'&&<>
       <label className="field">Ownership загружаемых файлов<select disabled={busy||!canFileWrite} value={ownership} onChange={e=>setOwnership(e.target.value as typeof ownership)}><option value="required">required</option><option value="managed">managed</option><option value="optional">optional</option></select></label>
       <label className="field">Импорт каталога Minecraft (включая вложенные папки)<input type="file" multiple disabled={busy||!canFileWrite} {...{'webkitdirectory':''}} onChange={e=>{void importFiles(e.target.files);e.target.value=''}}/></label>
       <label className="field">Или импорт отдельных файлов<input type="file" multiple disabled={busy||!canFileWrite} onChange={e=>{void importFiles(e.target.files);e.target.value=''}}/></label>
       <p className="muted">Для одиночных файлов сохраняется имя в корне сборки. Вложенные пути импортируйте каталогом. Личные файлы (saves, config, options.txt и др.) исключаются.</p>
     </>}
     <p aria-live="polite">{workspace.files.length} файлов · {workspace.files.filter(f=>f.selected).length} в последнем stage. {progress}</p>
     {scan&&<><p>Scan revision {scan.revision}: <strong>{scan.status}</strong> · проверено {scan.files.length}; ошибок {scan.files.filter(f=>f.status!=='ok').length}</p>
       {scan.files.filter(f=>f.status!=='ok').map(f=><p role="alert" key={f.path}><code>{f.path}</code>: {f.status}</p>)}
     </>}
     <label className="field">Базовая опубликованная версия
       <select disabled={busy} value={baseVersionId} onChange={e=>{setBaseVersionId(e.target.value);setComparison(null)}}><option value="">Без сравнения (все файлы новые)</option>{releases.filter(x=>x.profileId===profileId&&x.status==='published').map(x=><option key={x.id} value={x.id}>{x.version} · {x.channel}</option>)}</select>
     </label>
     <button disabled={busy} onClick={()=>void diff()}>Сравнить выбранные файлы с версией</button>
     {comparison&&<><p>Diff revision {comparison.revision}: {Object.entries(counts).map(([kind,count])=>`${kind}: ${count}`).join(' · ')||'нет изменений'}</p>
       <div style={{maxHeight:200,overflowY:'auto'}}><ul>{comparison.items.map(x=><li key={x.path}><code>{x.path}</code> — {x.change}{x.oldSha256&&x.newSha256&&x.oldSha256!==x.newSha256?` (${x.oldSha256.slice(0,10)}… → ${x.newSha256.slice(0,10)}…)`:''}</li>)}</ul></div></>}
     <label className="field">Фильтр файлов<input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="mods/"/></label>
     <div className="buttonRow"><button disabled={busy||workspace.state==='built'} onClick={()=>{setSelected(workspace.files.map(f=>f.path));setValidation(null)}}>Выбрать все</button><button disabled={busy||workspace.state==='built'} onClick={()=>{setSelected([]);setValidation(null)}}>Снять выбор</button></div>
     <div style={{maxHeight:300,overflowY:'auto'}} role="group" aria-label="Файлы сборки">{shown.slice(0,300).map(f=><div key={f.path} style={{display:'flex',alignItems:'center',gap:8}}>
       <label style={{flex:1,minWidth:0,overflowWrap:'anywhere'}}><input type="checkbox" disabled={busy||workspace.state==='built'} checked={selected.includes(f.path)} onChange={e=>{setSelected(v=>e.target.checked?[...v,f.path]:v.filter(x=>x!==f.path));setValidation(null)}}/>
       <code>{f.path}</code> · {f.size} B · {f.ownership} · {f.sha256.slice(0,12)}…</label>
       {workspace.state!=='built'&&<button type="button" disabled={busy||!canFileWrite} onClick={()=>void removeFile(f.path)}>Удалить</button>}
     </div>)}</div>
     {shown.length>300&&<p className="muted">Показано 300 из {shown.length} файлов — используйте фильтр.</p>}
     {workspace.state!=='built'&&<div className="buttonRow">
       <button disabled={busy||!canFileWrite||!selected.length} onClick={()=>void stage()}>Stage selected ({selected.length})</button>
       <button disabled={busy||workspace.state!=='staged'||selected.length!==workspace.files.filter(f=>f.selected).length||selected.some(x=>!workspace.files.some(f=>f.path===x&&f.selected))} onClick={()=>void validate()}>Validate staged files</button>
       <button disabled={busy||!canFileWrite||!validation?.valid||workspace.state!=='staged'||validation.fileCount!==selected.length||selected.some(x=>!workspace.files.some(f=>f.path===x&&f.selected))} onClick={()=>void build()}>Создать пакет и проверить файлы</button>
     </div>}
     {validation&&<p>Validated profile r{validation.profileRevision}: <code>{validation.buildDigest}</code> · {validation.fileCount} файлов. Сервер повторно проверит все файлы при сборке.</p>}
     {workspace.state==='built'&&<><p>Материализовано: <code>{workspace.packageId}</code> · <code>{workspace.buildDigest}</code>.</p>
       <div className="buttonRow"><button disabled={busy||!workspace.packageId} onClick={()=>void run(()=>verifyPackage(workspace))}>Сверить пакет с Workspace</button><button disabled={busy||!workspace.packageId} onClick={()=>void run(async()=>{await verifyPackage(workspace);await onBuilt(workspace.packageId!)})}>Привязать к черновику релиза</button></div>
       {materialized!==null&&<p role="status">{materialized?'Состав и SHA-256 в пакете совпадают с зафиксированным workspace.':'Обнаружено несовпадение пакета'}</p>}
     </>}
   </>}
   {error&&<p role="alert" className="error">{error}</p>}
 </article>;
}
