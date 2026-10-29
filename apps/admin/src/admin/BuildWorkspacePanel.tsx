import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {ClientFactoryBuilder02710} from './ClientFactoryBuilder02710';

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
const message=(e:unknown)=>e instanceof Error?e.message:String(e);
function managedPath(p:string){return !/^(saves|screenshots|resourcepacks|shaderpacks|config|logs|crash-reports|diagnostics|\.neverlauncher)(\/|$)/i.test(p)&& !/^(options\.txt|optionsof\.txt|servers\.dat|usercache\.json)$/i.test(p)}

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
 const [baseVersionId,setBaseVersionId]=useState('');
 const [comparison,setComparison]=useState<Array<{path:string;change:string}>>([]);
 const [scan,setScan]=useState<{status:string;files:Array<{path:string;status:string}>}|null>(null);
 const [validation,setValidation]=useState<{valid:boolean;buildDigest:string;fileCount:number}|null>(null);
 const [progress,setProgress]=useState('');
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const endpoint=useMemo(()=>base.replace(/\/$/,''),[base]);
 const api=useCallback(async<T,>(url:string,method:'GET'|'POST'='GET',payload?:unknown):Promise<T>=>{
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
 useEffect(()=>{setWorkspace(null);setScan(null);setComparison([]);setValidation(null);setSelected([]);void refresh().catch(e=>setError(message(e)))},[refresh]);
 const load=useCallback((ws:BuildWorkspace)=>{setWorkspace(ws);setSelected(ws.files.filter(f=>f.selected).map(f=>f.path));setScan(null);setValidation(null);setComparison([])},[]);
 async function run<T>(fn:()=>Promise<T>):Promise<T|undefined>{if(busy)return;setBusy(true);setError('');try{return await fn()}catch(e){setError(message(e));return undefined}finally{setBusy(false)}}
 async function create(){
   await run(async()=>{
     const settings:Settings=settingsJSON.trim()?JSON.parse(settingsJSON) as Settings:{minecraft:{version:minecraftVersion,loader,...(loaderVersion?{loaderVersion}:{})},runtime:{java:{majorVersion:javaMajor,distribution:'any'},memory:{minimumMb:512,recommendedMb:ram,maximumMb:Math.max(ram,8192)}}};
     if(!settings.minecraft?.version||!settings.runtime?.java?.majorVersion)throw new Error('Укажите Minecraft и Java в параметрах сборки');
     const ws=await api<BuildWorkspace>('/api/v1/build-workspaces','POST',{projectId,profileId,channel,version,settings});load(ws);await refresh();
   });
 }
 async function importDirectory(files:FileList|null){
   if(!workspace||!files?.length)return;
   await run(async()=>{
     let current=workspace;
     const list=Array.from(files);
     let skipped=0;let uploaded=0;
     for(const [i,file] of list.entries()){
       const relative=(file.webkitRelativePath||file.name).replace(/\\/g,'/');
       const parts=relative.split('/');const target=parts.length>1?parts.slice(1).join('/'):relative;
       if(!managedPath(target)){skipped++;continue}
       const body=new FormData();body.append('file',file);body.append('path',target);body.append('revision',String(current.revision));body.append('ownership','required');
       // Content is hashed and checked on the backend; never trust a JS-provided digest.
       setProgress(`Импорт ${i+1}/${list.length}: ${target}`);
       const res=await fetch(`${endpoint}/api/v1/build-workspaces/${encodeURIComponent(current.id)}/files`,{method:'POST',headers:{Authorization:`Bearer ${token}`},body,cache:'no-store'});
       const reply=await res.json() as Wrapped<BuildWorkspace>;
       if(!res.ok)throw new Error(`${target}: ${reply.error?.message||`HTTP ${res.status}`}`);
       current=reply.data;uploaded++;setWorkspace(current);
     }
     load(current);setProgress(`Импортировано ${uploaded}; пользовательских/защищённых файлов пропущено ${skipped}.`);await refresh();
   });
 }
 async function scanFiles(){if(!workspace)return;await run(async()=>setScan(await api(`/api/v1/build-workspaces/${workspace.id}/scan`)))}
 async function diff(){if(!workspace)return;await run(async()=>{const result=await api<{items:Array<{path:string;change:string}>}>(`/api/v1/build-workspaces/${workspace.id}/diff${baseVersionId?`?baseVersionId=${encodeURIComponent(baseVersionId)}`:''}`);setComparison(result.items)})}
 async function stage(){if(!workspace)return;await run(async()=>{const ws=await api<BuildWorkspace>(`/api/v1/build-workspaces/${workspace.id}/stage`,'POST',{revision:workspace.revision,paths:selected});load(ws)})}
 async function validate(){if(!workspace)return;await run(async()=>setValidation(await api(`/api/v1/build-workspaces/${workspace.id}/validate`)))}
 async function build(){if(!workspace)return;await run(async()=>{
   const ws=await api<BuildWorkspace>(`/api/v1/build-workspaces/${workspace.id}/build`,'POST',{revision:workspace.revision});load(ws);
   if(ws.packageId){await onBuilt(ws.packageId)}
 })}
 return <article className="subcard">
   <h4>Build Workspace · 0.22.6</h4>
   <p className="muted">Импорт папки → сканирование SHA-256 → сравнение → stage → проверка → сборка реального пакета. Файлы пользователя не импортируются.</p>
   {!workspace&&<>
     <label className="field">Java major <input type="number" min={8} max={255} disabled={!!profileMinecraftConfigured} value={javaMajor} onChange={e=>setJavaMajor(Number(e.target.value))}/></label>
     <label className="field">RAM recommended (MB) <input type="number" min={512} max={131072} value={ram} onChange={e=>setRam(Number(e.target.value))}/></label>
     <label className="field">Дополнительные настройки сборки (JSON, необязательно)<textarea rows={3} value={settingsJSON} onChange={e=>setSettingsJSON(e.target.value)} placeholder="minecraft, runtime, fileRules, toolVersions"/></label>
     <button disabled={busy||!version||!profileId||!minecraftVersion} onClick={()=>void create()}>Создать workspace</button>
     {items.length>0&&<><h5>Продолжить workspace</h5><ul>{items.map(x=><li key={x.id}><button disabled={busy} onClick={()=>load(x)}>{x.id} · {x.state} · r{x.revision}</button></li>)}</ul></>}
   </>}
   {workspace&&<>
     <ClientFactoryBuilder02710 backend={base} token={token} workspaceId={workspace.id} minecraft={workspace.settings.minecraft.version} loader={workspace.settings.minecraft.loader} initialLoaderVersion={workspace.settings.minecraft.loaderVersion||loaderVersion} canBuild={canFileWrite && workspace.state!=='built'} />
     <p>Workspace: <code>{workspace.id}</code> · {workspace.state} · revision {workspace.revision} · Profile revision {workspace.profileRevision}</p>
     <div className="buttonRow"><button disabled={busy} onClick={()=>{setWorkspace(null);void refresh()}}>Другой workspace</button><button disabled={busy} onClick={()=>void scanFiles()}>Scan / SHA-256</button></div>
     {workspace.state!=='built'&&<label className="field">Импорт каталога Minecraft (включая вложенные папки)
       <input type="file" multiple disabled={busy||!canFileWrite} {...{'webkitdirectory':''}} onChange={e=>{void importDirectory(e.target.files);e.target.value=''}}/>
     </label>}
     <p>{workspace.files.length} файлов. {progress}</p>
     {scan&&<p>Scan: <strong>{scan.status}</strong>, проверено {scan.files.length}</p>}
     <label className="field">Базовая опубликованная версия
       <select value={baseVersionId} onChange={e=>setBaseVersionId(e.target.value)}><option value="">Без сравнения (все файлы новые)</option>{releases.filter(x=>x.profileId===profileId&&x.status==='published').map(x=><option key={x.id} value={x.id}>{x.version}</option>)}</select>
     </label>
     <button disabled={busy} onClick={()=>void diff()}>Diff</button>
     {comparison.length>0&&<ul>{comparison.map(x=><li key={x.path}><code>{x.path}</code> — {x.change}</li>)}</ul>}
     <div style={{maxHeight:250,overflowY:'auto'}}>{workspace.files.map(f=><label key={f.path} style={{display:'block'}}>
       <input type="checkbox" disabled={busy||workspace.state==='built'} checked={selected.includes(f.path)} onChange={e=>setSelected(v=>e.target.checked?[...v,f.path]:v.filter(x=>x!==f.path))}/>
       <code>{f.path}</code> · {f.size} B · {f.sha256.slice(0,12)}…</label>)}</div>
     {workspace.state!=='built'&&<div className="buttonRow"><button disabled={busy||!selected.length} onClick={()=>void stage()}>Stage selected</button><button disabled={busy||workspace.state!=='staged'} onClick={()=>void validate()}>Validate</button><button disabled={busy||!validation?.valid||workspace.state!=='staged'} onClick={()=>void build()}>Build manifest &amp; package</button></div>}
     {validation&&<p>Build identity: <code>{validation.buildDigest}</code> · {validation.fileCount} файлов</p>}
     {workspace.state==='built'&&<p>Готово: <code>{workspace.packageId}</code> · <code>{workspace.buildDigest}</code>. Далее используйте штатные Sign, Stage, Integrity check и Publish. <button disabled={busy||!workspace.packageId} onClick={()=>void run(()=>onBuilt(workspace.packageId!))}>Привязать к черновику релиза</button></p>}
   </>}
   {error&&<p role="alert" className="error">{error}</p>}
 </article>;
}
