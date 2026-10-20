import React,{useCallback,useEffect,useMemo,useState} from 'react';
import type { ReleaseApi } from '../api/release';
import {type Catalog0248,type CatalogSnapshot0248,type CatalogPreview0248,type Component0248,type Category0248,type Group0248,type Preset0248,type Conditions0248,
 freshComponent0248,listAvailableFiles0248,lintCatalog0248,splitLines0248,parseRelations0248,formatRelations0248,renameComponent0248,removeComponent0248,validComponentID0248} from './component-editor-model-0248';

type Section='components'|'categories'|'groups'|'presets';
const errText=(e:unknown)=>e instanceof Error?e.message:String(e);
const lines=(values:string[]|undefined)=>(values||[]).join('\n');
function TextField({label,value,onChange,disabled=false}:{label:string;value:string;onChange:(v:string)=>void;disabled?:boolean}){
 return <label className="field"><span>{label}</span><input disabled={disabled} value={value} onChange={e=>onChange(e.target.value)}/></label>;
}
function MultiField({label,value,onChange,rows=3}:{label:string;value:string;onChange:(v:string)=>void;rows?:number}){
 return <label className="field"><span>{label}</span><textarea rows={rows} value={value} onChange={e=>onChange(e.target.value)}/></label>;
}
const initialCatalog=(source:Catalog0248):Catalog0248=>({...source,schemaVersion:'5.0',components:source.components.map(c=>({...c,visible:c.visible??true,version:c.version||'1.0.0'})),categories:source.categories||[],groups:source.groups||[],presets:source.presets||[]});

export function ComponentGraphEditor0248({api,packageId,canEdit,onChange}:{api:ReleaseApi;packageId:string;canEdit:boolean;onChange?:(blocked:boolean)=>void}){
 const [snapshot,setSnapshot]=useState<CatalogSnapshot0248|null>(null);
 const [catalog,setCatalog]=useState<Catalog0248|null>(null);
 const [section,setSection]=useState<Section>('components');
 const [selected,setSelected]=useState('');
 const [preview,setPreview]=useState<CatalogPreview0248|null>(null);
 const [previewKey,setPreviewKey]=useState('');
 const [saving,setSaving]=useState(false);
 const [error,setError]=useState('');
 const [notice,setNotice]=useState('');
 const [busy,setBusy]=useState(false);
 const [newName,setNewName]=useState('');
 const [search,setSearch]=useState('');
 const [showGraph,setShowGraph]=useState(true);
 const initialRevision=snapshot?.catalog?.revision??0;
 const dirty=!!catalog&&!!snapshot&&JSON.stringify(catalog)!==JSON.stringify(initialCatalog(snapshot.catalog!));
 const currentKey=useMemo(()=>catalog?JSON.stringify(catalog):'',[catalog]);
 const eligible=!!snapshot&&snapshot.status==='draft'&&snapshot.manifestSchemaVersion==='3.0';
 const usable=canEdit&&eligible&&!busy&&!saving;
 const localErrors=useMemo(()=>catalog&&snapshot?lintCatalog0248(catalog,snapshot.files):[],[catalog,snapshot]);
 const validated=!!preview?.valid&&previewKey===currentKey;
 const blocked=dirty||!validated&&!!catalog&&localErrors.length>0;
 const load=useCallback(async()=>{
  const loaded=await api.componentEditorGet(packageId);
  setSnapshot(loaded);setCatalog(loaded.catalog?initialCatalog(loaded.catalog):null);
  setSelected(loaded.catalog?.components[0]?.id||'');setPreview(null);setPreviewKey('');setError('');setNotice('');
 },[api,packageId]);
 useEffect(()=>{let live=true;setSnapshot(null);setCatalog(null);setBusy(true);api.componentEditorGet(packageId)
  .then(r=>{if(!live)return;setSnapshot(r);setCatalog(r.catalog?initialCatalog(r.catalog):null);setSelected(r.catalog?.components[0]?.id||'');setPreview(null);setPreviewKey('')})
  .catch(e=>{if(live)setError(errText(e))}).finally(()=>{if(live)setBusy(false)});
  return()=>{live=false};},[api,packageId]);
 useEffect(()=>{onChange?.(blocked)},[blocked,onChange]);
 function edit(next:Catalog0248){setCatalog(next);setPreview(null);setPreviewKey('');setError('');setNotice('')}
 const components=catalog?.components||[];
 const component=components.find(c=>c.id===selected);
 const categories=catalog?.categories||[];
 const groups=catalog?.groups||[];
 const presets=catalog?.presets||[];
 function changeComponent(update:Partial<Component0248>){if(!catalog||!component)return;edit({...catalog,components:catalog.components.map(c=>c.id===selected?{...c,...update}:c)})}
 function renameComponent(newID:string){if(!catalog||!component||newID===selected)return;
  if(!validComponentID0248(newID)||components.some(c=>c.id===newID)){setError('ID должен быть уникальным и соответствовать [a-z0-9._-].');return;}
  edit(renameComponent0248(catalog,selected,newID));setSelected(newID);
 }
 function addEntry(){if(!catalog)return;const id=newName.trim();
  if(!validComponentID0248(id)){setError('Нужен корректный ID: латиница нижнего регистра, цифры, ._-');return;}
  if((section==='components'&&components.some(c=>c.id===id))||(section==='categories'&&categories.some(c=>c.id===id))||(section==='groups'&&groups.some(c=>c.id===id))||(section==='presets'&&presets.some(c=>c.id===id))){setError('ID уже существует');return;}
  if(section==='components'){const candidates=listAvailableFiles0248(catalog,snapshot?.files||[],id);edit({...catalog,components:[...components,freshComponent0248(id,candidates.length===1?[candidates[0].path]:[])]})}
  if(section==='categories')edit({...catalog,categories:[...categories,{id,name:id}]});
  if(section==='groups')edit({...catalog,groups:[...groups,{id,name:id}]});
  if(section==='presets')edit({...catalog,presets:[...presets,{id,name:id,components:[]}]});
  setSelected(id);setNewName('');
 }
 function changeCategory(updated:Category0248){if(!catalog)return;edit({...catalog,categories:categories.map(x=>x.id===selected?updated:x)})}
 function changeGroup(updated:Group0248){if(!catalog)return;edit({...catalog,groups:groups.map(x=>x.id===selected?updated:x)})}
 function changePreset(updated:Preset0248){if(!catalog)return;edit({...catalog,presets:presets.map(x=>x.id===selected?updated:x)})}
 function removeEntry(){if(!catalog||!selected||!window.confirm(`Удалить ${selected}? Ссылки из пресетов и графа будут очищены.`))return;
  if(section==='components')edit(removeComponent0248(catalog,selected));
  if(section==='categories')edit({...catalog,categories:categories.filter(x=>x.id!==selected),groups:groups.map(g=>({...g,categoryId:g.categoryId===selected?undefined:g.categoryId})),components:components.map(c=>({...c,categoryId:c.categoryId===selected?undefined:c.categoryId}))});
  if(section==='groups')edit({...catalog,groups:groups.filter(x=>x.id!==selected).map(g=>({...g,parentId:g.parentId===selected?undefined:g.parentId})),components:components.map(c=>({...c,groupId:c.groupId===selected?undefined:c.groupId}))});
  if(section==='presets')edit({...catalog,presets:presets.filter(p=>p.id!==selected),defaultPreset:catalog.defaultPreset===selected?undefined:catalog.defaultPreset});
  setSelected('');
 }
 async function runPreview(){if(!catalog||!snapshot)return;setBusy(true);setError('');setNotice('');
  try{const key=JSON.stringify(catalog);const result=await api.componentEditorPreview(packageId,{expectedRevision:initialRevision,catalog});setPreview(result);setPreviewKey(key);
   if(result.valid)setNotice('Backend подтвердил корректность каталога и пресетов.');
  }catch(e){setPreview(null);setPreviewKey('');setError(errText(e))}finally{setBusy(false)}
 }
 async function save(){if(!catalog||!snapshot||!validated||!dirty)return;setSaving(true);setError('');
  try{const result=await api.componentEditorSave(packageId,{expectedRevision:initialRevision,catalog});
   setSnapshot({...snapshot,catalog:result.catalog,status:result.status});setCatalog(initialCatalog(result.catalog));
   setPreview(null);setPreviewKey('');setNotice(`Каталог r${result.catalog.revision} сохранён. Digest ${result.catalog.digest.slice(0,16)}…`);
  }catch(e){setError(errText(e));setPreview(null);setPreviewKey('')}finally{setSaving(false)}
 }
 if(busy&&!snapshot)return <article className="subcard"><h4>Редактор компонентов</h4><p>Загрузка каталога из Backend…</p></article>;
 if(!snapshot||!catalog)return <article className="subcard"><h4>Редактор компонентов</h4><p role="alert" className="error">{error||'Каталог не найден'}</p></article>;
 const catEntry=categories.find(c=>c.id===selected);
 const groupEntry=groups.find(c=>c.id===selected);
 const presetEntry=presets.find(c=>c.id===selected);
 const availableFiles=component?listAvailableFiles0248(catalog,snapshot.files,component.id):[];
 const entries=section==='components'?components:section==='categories'?categories:section==='groups'?groups:presets;
 return <article className="subcard componentEditor0248">
  <h4>Component Graph Editor · 0.24.8</h4>
  <p className="muted">Manifest {snapshot.manifestSchemaVersion} · Catalog {snapshot.catalog?.schemaVersion} r{initialRevision} · SHA-256 {snapshot.catalog?.digest?.slice(0,16)}… · {snapshot.status}</p>
  {!eligible&&<p role="alert" className="error">Редактирование доступно только в неподписанном Manifest v3. Создайте новый v3-пакет; подписанные и опубликованные релизы неизменяемы.</p>}
  <div className="buttonRow"><button disabled={busy||saving||dirty} onClick={()=>void load()}>Перечитать с Backend</button><button disabled={!dirty||busy||saving} onClick={()=>{if(window.confirm('Сбросить несохранённые изменения?')){setCatalog(initialCatalog(snapshot.catalog!));setPreview(null);setPreviewKey('')}}}>Сбросить правки</button></div>
  <fieldset disabled={!usable}>
   <nav className="buttonRow" aria-label="Раздел каталога">{(['components','categories','groups','presets'] as Section[]).map(kind=><button type="button" key={kind} aria-pressed={section===kind} onClick={()=>{setSection(kind);setSelected('')}}>{({components:'Компоненты',categories:'Категории',groups:'Группы',presets:'Пресеты'})[kind]}</button>)}</nav>
   <div className="componentEditorLayout0248">
    <div className="componentEditorList0248">
     <input aria-label="Поиск в каталоге" placeholder="Поиск по ID или названию" value={search} onChange={e=>setSearch(e.target.value)}/>
     {entries.filter(x=>(x.id+' '+x.name).toLowerCase().includes(search.toLowerCase())).map(x=><button key={x.id} type="button" aria-pressed={selected===x.id} className="componentEditorItem0248" onClick={()=>setSelected(x.id)}>{x.name} <code>{x.id}</code></button>)}
     <label className="field">Новый ID<input value={newName} onChange={e=>setNewName(e.target.value)} placeholder="my-component"/></label>
     <button type="button" disabled={!newName.trim()} onClick={addEntry}>Добавить</button>
    </div>
    <div className="componentEditorDetails0248">
     {!selected&&<p className="muted">Выберите объект слева или добавьте новый. Файлы должны сначала быть загружены с ownership=optional.</p>}
     {component&&section==='components'&&<>
      <TextField label="ID компонента (стабильный)" value={component.id} onChange={renameComponent}/>
      <TextField label="Название" value={component.name} onChange={name=>changeComponent({name})}/>
      <MultiField label="Описание" value={component.description||''} onChange={description=>changeComponent({description})} rows={2}/>
      <TextField label="SemVer" value={component.version||''} onChange={version=>changeComponent({version})}/>
      <div className="componentEditorFlags0248">{(['required','default','visible','limited'] as const).map(flag=><label key={flag}><input type="checkbox" checked={!!component[flag]} onChange={e=>changeComponent({[flag]:e.target.checked})}/>{flag}</label>)}</div>
      <label className="field">Категория<select value={component.categoryId||''} onChange={e=>changeComponent({categoryId:e.target.value||undefined})}><option value="">Без категории</option>{categories.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
      <label className="field">Группа<select value={component.groupId||''} onChange={e=>changeComponent({groupId:e.target.value||undefined})}><option value="">Без группы</option>{groups.map(g=><option key={g.id} value={g.id}>{g.name}</option>)}</select></label>
      <TextField label="Взаимоисключающая группа" value={component.exclusiveGroup||''} onChange={exclusiveGroup=>changeComponent({exclusiveGroup})}/>
      <h5>Подписанные файлы</h5>
      {availableFiles.map(f=><label key={f.path} className="componentEditorFile0248"><input type="checkbox" checked={component.files.includes(f.path)} onChange={e=>changeComponent({files:e.target.checked?[...component.files,f.path]:component.files.filter(p=>p!==f.path),actions:!e.target.checked?component.actions?.filter(a=>a.path!==f.path):component.actions})}/><code>{f.path}</code> ({f.size} B)</label>)}
      {!availableFiles.length&&<p className="muted">Свободных optional-файлов нет. Загрузите их в пакет перед назначением.</p>}
      <MultiField label="Зависимости (ID [SemVer range], по одной на строке)" value={formatRelations0248(component.dependencies)} onChange={t=>changeComponent({dependencies:parseRelations0248(t)})}/>
      <MultiField label="Конфликты (ID [SemVer range])" value={formatRelations0248(component.conflicts)} onChange={t=>changeComponent({conflicts:parseRelations0248(t)})}/>
      <h5>Условия (schema 1.0)</h5>
      <label><input type="checkbox" checked={!!component.conditions} onChange={e=>changeComponent({conditions:e.target.checked?{schemaVersion:'1.0'}:undefined})}/> Ограничить доступность</label>
      {component.conditions&&<>
       {(['os','arch','minecraftVersions','loaders','permissions'] as const).map(key=><MultiField key={key} label={key+' (список)'} rows={2} value={lines(component.conditions?.[key])} onChange={t=>changeComponent({conditions:{...component.conditions!,[key]:splitLines0248(t)}})}/>)}
       {(['minecraftVersionRange','loaderVersionRange'] as const).map(key=><TextField key={key} label={key} value={component.conditions?.[key]||''} onChange={v=>changeComponent({conditions:{...component.conditions!,[key]:v}})}/>)}
       {(['javaMajorMin','javaMajorMax'] as const).map(key=><label className="field" key={key}>{key}<input type="number" min={0} max={99} value={component.conditions?.[key]||0} onChange={e=>changeComponent({conditions:{...component.conditions!,[key]:Number(e.target.value)}})}/></label>)}
      </>}
      <h5>Optional Actions (подписываемые)</h5>
      {(component.actions||[]).map((a,i)=><div className="componentEditorAction0248" key={i}>
       <label className="field">Тип<select value={a.type} onChange={e=>changeComponent({actions:(component.actions||[]).map((v,j)=>j===i?{type:e.target.value as typeof a.type}:v)})}>{['File','ClassPath','JvmArgs','ClientArgs'].map(t=><option key={t}>{t}</option>)}</select></label>
       {(a.type==='File'||a.type==='ClassPath')?<label className="field">Файл<select value={a.path||''} onChange={e=>changeComponent({actions:component.actions?.map((v,j)=>j===i?{...v,path:e.target.value}:v)})}><option value="">Выберите файл</option>{component.files.filter(p=>a.type!=='ClassPath'||p.toLowerCase().endsWith('.jar')).map(p=><option key={p} value={p}>{p}</option>)}</select></label>
       :<MultiField label="Аргументы (по одному на строке)" rows={2} value={lines(a.args)} onChange={text=>changeComponent({actions:component.actions?.map((v,j)=>j===i?{...v,args:splitLines0248(text)}:v)})}/>}
       <button type="button" onClick={()=>changeComponent({actions:component.actions?.filter((_,j)=>j!==i)})}>Удалить действие</button>
      </div>)}
      <button type="button" onClick={()=>changeComponent({actions:[...(component.actions||[]),{type:'File',path:component.files[0]||''}]})}>Добавить действие</button>
      <MultiField label="Метаданные (key=value)" value={Object.entries(component.metadata||{}).map(([k,v])=>`${k}=${v}`).join('\n')} onChange={t=>{const metadata:Record<string,string>={};for(const line of t.split('\n')){const i=line.indexOf('=');if(i>0)metadata[line.slice(0,i).trim()]=line.slice(i+1)}changeComponent({metadata})}}/>
     </>}
     {catEntry&&section==='categories'&&<>
      <TextField label="Название" value={catEntry.name} onChange={name=>changeCategory({...catEntry,name})}/><MultiField label="Описание" value={catEntry.description||''} onChange={description=>changeCategory({...catEntry,description})} rows={2}/>
      <label className="field">Родительская категория<select value={catEntry.parentId||''} onChange={e=>changeCategory({...catEntry,parentId:e.target.value||undefined})}><option value="">Корневая</option>{categories.filter(c=>c.id!==selected).map(c=><option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
     </>}
     {groupEntry&&section==='groups'&&<>
      <TextField label="Название" value={groupEntry.name} onChange={name=>changeGroup({...groupEntry,name})}/><MultiField label="Описание" value={groupEntry.description||''} onChange={description=>changeGroup({...groupEntry,description})} rows={2}/>
      <label className="field">Родительская группа<select value={groupEntry.parentId||''} onChange={e=>changeGroup({...groupEntry,parentId:e.target.value||undefined})}><option value="">Корневая</option>{groups.filter(g=>g.id!==selected).map(g=><option key={g.id} value={g.id}>{g.name}</option>)}</select></label>
      <label className="field">Категория<select value={groupEntry.categoryId||''} onChange={e=>changeGroup({...groupEntry,categoryId:e.target.value||undefined})}><option value="">Не указана</option>{categories.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
     </>}
     {presetEntry&&section==='presets'&&<>
      <TextField label="Название пресета" value={presetEntry.name} onChange={name=>changePreset({...presetEntry,name})}/><MultiField label="Описание" value={presetEntry.description||''} onChange={description=>changePreset({...presetEntry,description})} rows={2}/>
      <label><input type="checkbox" checked={catalog.defaultPreset===presetEntry.id} onChange={e=>edit({...catalog,defaultPreset:e.target.checked?presetEntry.id:undefined})}/> Пресет по умолчанию</label>
      <h5>Выбранные компоненты</h5>{components.map(c=><label key={c.id} className="componentEditorFile0248"><input type="checkbox" checked={presetEntry.components.includes(c.id)} onChange={e=>changePreset({...presetEntry,components:e.target.checked?[...presetEntry.components,c.id]:presetEntry.components.filter(id=>id!==c.id)})}/>{c.name} <code>{c.id}</code></label>)}
     </>}
     {!!selected&&<div className="buttonRow"><button type="button" onClick={removeEntry}>Удалить объект</button></div>}
    </div>
   </div>
  </fieldset>
  {showGraph&&<div className="componentEditorGraph0248"><h5>Граф зависимостей и конфликтов</h5><ul>{components.map(c=><li key={c.id}><strong>{c.id}</strong>{c.dependencies?.length?' → '+c.dependencies.map(r=>r.id+(r.versionRange?' ('+r.versionRange+')':'')).join(', '):''}{c.conflicts?.length?' · конфликтует: '+c.conflicts.map(r=>r.id).join(', '):''}{c.exclusiveGroup?' · exclusive '+c.exclusiveGroup:''}</li>)}</ul></div>}
  <button onClick={()=>setShowGraph(v=>!v)}>{showGraph?'Скрыть граф':'Показать граф'}</button>
  {localErrors.length>0&&<div role="alert" className="error"><strong>Локальные замечания:</strong><ul>{localErrors.map((x,i)=><li key={i}>{x}</li>)}</ul></div>}
  {preview&&<div className="releaseEffect" role="status"><strong>{preview.valid?'Backend: проверка пройдена':'Backend: каталог недопустим'}</strong><p>Revision r{preview.revision} · digest <code>{preview.digest}</code></p>
   {preview.errors.length>0&&<ul>{preview.errors.map((e,i)=><li key={i}>{e}</li>)}</ul>}
   <h5>Проверка всех пресетов</h5><ul>{preview.presets.map((p,i)=><li key={i}>{p.preset||'(default)'}: {p.error||p.selected?.join(', ')||'пустой набор'}</li>)}</ul>
   <p className="muted">Условия OS/Java/loader и permissions повторно проверяются native runtime при установке. Серверный граф-preview не является доказательством полномочий пользователя.</p>
  </div>}
  <div className="buttonRow"><button disabled={!usable||!!localErrors.length} onClick={()=>void runPreview()}>Проверить на Backend</button>
   <button disabled={!usable||!dirty||!validated||!!localErrors.length} onClick={()=>void save()}>Сохранить проверенный каталог</button></div>
  {dirty&&<p className="muted">Каталог изменён; для сохранения требуется успешный свежий предпросмотр Backend.</p>}
  {notice&&<p role="status" className="success">{notice}</p>}
  {error&&<p role="alert" className="error">{error}</p>}
 </article>;
}
