import React,{useState} from 'react';
import type {ReleaseApi} from '../api/release';
import type {Catalog0248,CatalogPreview0248} from './component-editor-model-0248';

type Field={field:string;status:'mapped'|'transformed'|'manual'|'blocked';target?:string;reason:string};
export type GravitOptionalResponse02411={
 migration:{format:string;sourceSha256:string;ready:boolean;catalog:Catalog0248;fields:Field[];summary:Record<string,number>};
 preview:CatalogPreview0248;canApply:boolean;warning:string;
};

export function GravitOptionalImport02411({api,packageId,revision,enabled,onCandidate}:{
 api:ReleaseApi;packageId:string;revision:number;enabled:boolean;onCandidate:(candidate:Catalog0248)=>void;
}){
 const [source,setSource]=useState('');const [result,setResult]=useState<GravitOptionalResponse02411|null>(null);
 const [busy,setBusy]=useState(false);const [error,setError]=useState('');
 async function load(file:File|null){setResult(null);setError('');if(!file)return;
  if(file.size>1024*1024){setError('Лимит Gravit ClientProfile: 1 МБ');return}
  setSource(await file.text());
 }
 async function inspect(){setBusy(true);setError('');setResult(null);
  try{setResult(await api.componentEditorGravitPreview(packageId,revision,source))}
  catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}
 }
 function downloadReport(){if(!result)return;const body=JSON.stringify({format:result.migration.format,sourceSha256:result.migration.sourceSha256,ready:result.canApply,fields:result.migration.fields,summary:result.migration.summary,validation:result.preview},null,2)+'\n';const u=URL.createObjectURL(new Blob([body],{type:'application/json'}));
  try{const a=document.createElement('a');a.href=u;a.download='gravit-optional-migration-report.json';a.click()}finally{URL.revokeObjectURL(u)}
 }
 return <section className="subcard" aria-label="Gravit OptionalView migration">
  <h5>Импорт Gravit OptionalFile / OptionalView · 0.24.11</h5>
  <p>Импортируются поддерживаемые действия, зависимости, конфликты и обязательные триггеры из updateOptional. Файлы сначала загружаются как optional в текущий draft. Миграция не исполняет код и не изменяет подписанные релизы.</p>
  <label className="field"><span>Gravit ClientProfile или updateOptional JSON</span><input type="file" accept=".json,application/json" disabled={!enabled||busy} onChange={e=>void load(e.target.files?.[0]||null)}/></label>
  <div className="buttonRow"><button disabled={!enabled||busy||!source} onClick={()=>void inspect()}>Проверить перенос Gravit</button>{result&&<button onClick={downloadReport}>Скачать отчёт несовместимостей</button>}</div>
  {result&&<div role="status"><p><strong>{result.canApply?'Конвертация пригодна для предпросмотра':'Обнаружены несовместимости — требуется ручная правка'}</strong> · преобразовано: {result.migration.summary.transformed} · сопоставлено: {result.migration.summary.mapped} · вручную: {result.migration.summary.manual} · заблокировано: {result.migration.summary.blocked}</p>
   <p>SHA-256 Gravit JSON: <code>{result.migration.sourceSha256}</code></p>
   <div style={{maxHeight:260,overflowY:'auto'}}><table><thead><tr><th>Путь</th><th>Статус</th><th>Обоснование</th></tr></thead><tbody>{result.migration.fields.map((f,i)=><tr key={f.field+'-'+i}><td><code>{f.field}</code></td><td>{f.status}</td><td>{f.reason}{f.target&&<> → <code>{f.target}</code></>}</td></tr>)}</tbody></table></div>
   {result.preview.errors.length>0&&<ul>{result.preview.errors.map((e,i)=><li key={i}>{e}</li>)}</ul>}
   <p>Следующее действие загрузит результат в редактор, но <strong>не сохранит</strong> каталог. Проверка Backend и отдельное сохранение обязательны.</p>
   <button disabled={!enabled||busy||!result.canApply} onClick={()=>{onCandidate(result.migration.catalog);setResult(null)}}>Перенести в редактор для проверки</button>
  </div>}
  {error&&<p role="alert" className="error">{error}</p>}
 </section>;
}
