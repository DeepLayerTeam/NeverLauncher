import React, { useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type Field = {field:string;status:'mapped'|'transformed'|'manual'|'blocked';target?:string;reason:string};
type Report = {
 format:string;sourceSha256:string;ready:boolean;
 profile:{id:string;name:string;loader:string};
 settings:{minecraft:{version:string;loader:string};runtime:unknown;fileRules:unknown[]};
 servers:Array<{name:string;address:string;port:number;default:boolean}>;
 fields:Field[];summary:Record<string,number>;
};
type Imported = {report:Report;profile:{id:string};workspace:{id:string;state:string}};
export function GravitImportPanel({backendUrl,token,projectId,onChanged}:{backendUrl:string;token:string;projectId:string;onChanged:()=>Promise<void>}) {
 const [inputFile,setInputFile]=useState<File|null>(null);
 const [source,setSource]=useState<unknown>(null);
 const [id,setId]=useState('');
 const [name,setName]=useState('');
 const [loaderHint,setLoaderHint]=useState('vanilla');
 const [releaseVersion,setReleaseVersion]=useState('');
 const [channel,setChannel]=useState('stable');
 const [report,setReport]=useState<Report|null>(null);
 const [created,setCreated]=useState<Imported|null>(null);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const url=`/api/v1/admin/projects/${encodeURIComponent(projectId)}/profiles`;
 useEffect(()=>{setReport(null);setCreated(null)},[source,id,name,loaderHint,projectId]);
 async function loadFile(file:File|null){setInputFile(file);setSource(null);setError('');if(!file)return;
  if(file.size>1024*1024){setError('Максимальный размер JSON — 1 МБ');return}
  try {const value:unknown=JSON.parse(await file.text());if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Ожидается JSON-объект ClientProfile');setSource(value)}
  catch(e){setError(`Некорректный JSON: ${String(e)}`)}
 }
 const payload=()=>({id,name,loaderHint,source});
 const post=async<T,>(endpoint:string,body:unknown)=>requestJSON<T>(backendUrl,`${url}/${endpoint}`,token,{method:'POST',body:JSON.stringify(body)});
 async function inspect(){if(!source)return;setBusy(true);setError('');setReport(null);setCreated(null);
  try {setReport(await post<Report>('inspect-gravit',payload()))}catch(e){setError(String(e))}finally{setBusy(false)}
 }
 async function commit(){if(!source||!report?.ready)return;setBusy(true);setError('');
  try {const value=await post<Imported>('import-gravit',{...payload(),sourceSha256:report.sourceSha256,channel,version:releaseVersion});setCreated(value);await onChanged()}
  catch(e){setError(`${String(e)}. При сетевой ошибке проверьте список профилей и workspace перед повторной попыткой.`)}finally{setBusy(false)}
 }
 function downloadReport(){if(!report)return;const body=JSON.stringify(report,null,2)+'\n';const u=URL.createObjectURL(new Blob([body],{type:'application/json'}));
  try{const a=document.createElement('a');a.href=u;a.download=`gravit-import-${id||'profile'}.report.json`;a.click()}finally{setTimeout(()=>URL.revokeObjectURL(u),1000)}
 }
 return <section className="subcard" aria-label="Импорт ClientProfile Gravit">
  <h4>Статический импорт Gravit · 0.22.10</h4>
  <p>Анализирует JSON ClientProfile без выполнения кода. Поддерживаемые настройки попадут в новый приватный Build Workspace. Неподдерживаемые действия, загрузчики и правила блокируют создание, а не пропускаются молча.</p>
  <label className="field"><span>Gravit ClientProfile (.json, без комментариев)</span><input type="file" accept=".json,application/json" onChange={e=>void loadFile(e.target.files?.[0]||null)}/></label>
  {inputFile&&<p>Источник: {inputFile.name}</p>}
  <label className="field"><span>ID нового профиля</span><input value={id} onChange={e=>setId(e.target.value)} placeholder="imported-vanilla"/></label>
  <label className="field"><span>Новое название (необязательно)</span><input value={name} onChange={e=>setName(e.target.value)}/></label>
  <label className="field"><span>Тип загрузчика (проверить вручную)</span><select value={loaderHint} onChange={e=>setLoaderHint(e.target.value)}>{['vanilla','fabric','quilt','forge','neoforge'].map(x=><option value={x} key={x}>{x}</option>)}</select></label>
  <div className="buttonRow"><button disabled={busy||!source||!id||!projectId} onClick={()=>void inspect()}>Проверить и построить отчёт</button>{report&&<button disabled={busy} onClick={downloadReport}>Скачать отчёт JSON</button>}</div>
  {report&&<div role="status">
   <p><strong>{report.ready?'Все поля сопоставлены':'Требуется исправление источника или ручной перенос'}</strong>. Mapped: {report.summary.mapped}; transformed: {report.summary.transformed}; manual: {report.summary.manual}; blocked: {report.summary.blocked}</p>
   <p>SHA-256 источника: <code>{report.sourceSha256}</code></p>
   <div style={{maxHeight:360,overflowY:'auto'}}><table><thead><tr><th>Поле</th><th>Статус</th><th>Назначение и причина</th></tr></thead><tbody>{report.fields.map((f,i)=><tr key={`${f.field}-${i}`}><td><code>{f.field}</code></td><td>{f.status}</td><td>{f.target&&<code>{f.target}</code>} {f.reason}</td></tr>)}</tbody></table></div>
   {report.servers.length>0&&<p>Серверы ({report.servers.length}) перечислены для ручной регистрации в ServerBridge; конфигурация доступа автоматически не переносится.</p>}
   {report.ready&&<>
    <label className="field"><span>Новая версия сборки</span><input value={releaseVersion} onChange={e=>setReleaseVersion(e.target.value)} placeholder="1.0.0"/></label>
    <label className="field"><span>Канал</span><input value={channel} onChange={e=>setChannel(e.target.value)}/></label>
    <button disabled={busy||!releaseVersion||!channel} onClick={()=>void commit()}>Создать профиль и Build Workspace</button>
   </>}
  </div>}
  {created&&<p role="status">Профиль <code>{created.profile.id}</code> создан. Workspace <code>{created.workspace.id}</code> готов к импорту каталога и проверке реальных SHA-256 перед публикацией.</p>}
  {error&&<p role="alert">{error}</p>}
 </section>;
}
