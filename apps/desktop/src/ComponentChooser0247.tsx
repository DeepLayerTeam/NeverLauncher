import React, {useEffect,useMemo,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {parseChoice0247,proposeChoice0247, type SelectableComponent0247} from './component_selection_0247';

type CatalogComponent=SelectableComponent0247 & {description?:string;categoryId?:string;groupId?:string;version?:string;metadata?:Record<string,string>;actions?:{type:string}[]};
type Catalog={schemaVersion:string;revision:number;digest:string;components:CatalogComponent[];defaultPreset?:string;presets?:{id:string;name:string;description?:string;components:string[]}[];categories?:{id:string;name:string}[]};
type Manifest={componentCatalog?:Catalog;files:{path:string;size:number}[];version:string};
type Preview={selected:string[];unavailable:{id:string;reason:string}[];effectiveFiles:string[];reasons:{id:string;reason:string}[]};
type Diff={installedPreset:string|null;addedFiles:string[];removedFiles:string[];downloadFiles:string[];downloadBytesUpperBound:number;totalSelectedBytes:number;planSha256:string};
type Candidate={value:string;removed:string[];added:string[]};
const formatBytes=(bytes:number)=>bytes>=1048576?`${(bytes/1048576).toFixed(2)} МиБ`:`${(bytes/1024).toFixed(1)} КиБ`;

export function ComponentChooser0247({manifest,componentPreset,pinnedPublicKey,root,transferBusy,installSelection,topologyLabel}:
  {manifest:Manifest;componentPreset:string;pinnedPublicKey:string;root:string;
   transferBusy:boolean;installSelection:(choice:string)=>Promise<void>;topologyLabel:(c:CatalogComponent)=>string}){
  const cat=manifest.componentCatalog;
  const [current,setCurrent]=useState<Preview|null>(null);
  const [currentError,setCurrentError]=useState('');
  const [pending,setPending]=useState<Candidate|null>(null);
  const [preview,setPreview]=useState<Preview|null>(null);
  const [diff,setDiff]=useState<Diff|null>(null);
  const [error,setError]=useState('');
  const [actionError,setActionError]=useState('');
  const [installing,setInstalling]=useState(false);
  const [search,setSearch]=useState('');
  const [category,setCategory]=useState('');
  const [working,setWorking]=useState(false);
  const canEdit=Boolean(cat&&['2.0','3.0','4.0','5.0'].includes(cat.schemaVersion));
  const request=(value:string)=>invoke<Preview>('preview_components_0244',{
    manifest,pinnedPublicKey,componentPreset:value||null,
  });
  useEffect(()=>{
    let cancelled=false;
    setCurrent(null);setCurrentError('');setPending(null);setPreview(null);setDiff(null);
    if(!cat)return;
    request(componentPreset).then(result=>{if(!cancelled)setCurrent(result);})
      .catch(e=>{if(!cancelled)setCurrentError(String(e));});
    return ()=>{cancelled=true;};
  },[manifest,cat?.digest,componentPreset,pinnedPublicKey]);
  useEffect(()=>{
    let cancelled=false;
    setPreview(null);setDiff(null);setError('');
    if(!pending||!cat)return;
    setWorking(true);
    Promise.all([
      request(pending.value),
      invoke<Diff>('preview_component_changes_0247',{
        manifest,pinnedPublicKey,root,componentPreset:pending.value||null,
      }),
    ]).then(([result,changes])=>{if(!cancelled){setPreview(result);setDiff(changes);}})
      .catch(e=>{if(!cancelled)setError(String(e));})
      .finally(()=>{if(!cancelled)setWorking(false);});
    return ()=>{cancelled=true;};
  },[pending,manifest,pinnedPublicKey,root]);
  const selected=new Set(current?.selected||[]);
  const selectedNext=new Set(preview?.selected||[]);
  const reasons=new Map((pending?preview:current)?.reasons?.map(x=>[x.id,x.reason])||[]);
  const unavailable=new Map(current?.unavailable?.map(x=>[x.id,x.reason])||[]);
  const visible=useMemo(()=>{
    if(!cat)return [];
    return cat.components.filter(c=>(c.visible!==false||selected.has(c.id))&&
      (!category||c.categoryId===category)&&
      (`${c.name} ${c.id} ${c.description||''}`.toLowerCase().includes(search.toLowerCase())));
  },[cat,category,search,current]);
  function changeComponent(id:string,enable:boolean){
    if(!cat||!current||pending||transferBusy)return;
    try{
      setActionError('');
      const choice=proposeChoice0247(componentPreset,cat.components,current.selected,id,enable);
      setPending({value:choice.choice,removed:choice.removed,added:choice.added});
    }catch(e){setActionError(String(e));}
  }
  function changePreset(base:string){
    if(!cat||pending||transferBusy)return;
    setActionError('');
    const removed=current?.selected||[];
    setPending({value:base,removed,added:[]});
  }
  const currentBase=(()=>{try{return parseChoice0247(componentPreset).base;}catch{return ''}})();
  if(!cat)return null;
  return <article className="card componentChooser0247">
    <h3>Компоненты подписанного релиза <small>revision {cat.revision}</small></h3>
    <p>Индивидуальный выбор сохраняет подпись и состав каталога. Изменения применяются только после установки соответствующего resolved plan.</p>
    <div className="componentChooserFilters0247">
      <label>Базовый пресет<select disabled={!canEdit||Boolean(pending)||transferBusy} value={currentBase} onChange={e=>changePreset(e.target.value)}>
        <option value="">По умолчанию{cat.defaultPreset?` (${cat.defaultPreset})`:''}</option>
        {cat.presets?.map(p=><option value={p.id} key={p.id}>{p.name}</option>)}
      </select></label>
      <label>Категория<select value={category} onChange={e=>setCategory(e.target.value)}><option value="">Все категории</option>
        {cat.categories?.map(c=><option value={c.id} key={c.id}>{c.name}</option>)}
      </select></label>
      <label>Поиск<input value={search} placeholder="Название или ID" onChange={e=>setSearch(e.target.value)}/></label>
    </div>
    {!canEdit&&<p>Каталог v1 фиксирован и не поддерживает индивидуальный выбор.</p>}
    {currentError&&<p role="alert" className="error">Native проверка: {currentError}</p>}
    {actionError&&<p role="alert" className="error">{actionError}</p>}
    {!current&&!currentError&&<p role="status">Проверка подписанного выбора…</p>}
    <p role="status">Выбрано: {selected.size} из {cat.components.length}. Обязательные и транзитивные зависимости отображаются отдельно.</p>
    <div className="componentList0247">
      {visible.map(c=>{
        const checked=selected.has(c.id);
        const blocked=c.required||c.limited||c.visible===false||!canEdit||!current||Boolean(pending)||transferBusy;
        const unavailableReason=unavailable.get(c.id);
        return <label key={c.id} className={`componentItem0247 ${checked?'selected':''}`}>
          <input type="checkbox" checked={checked} disabled={blocked||Boolean(unavailableReason&&!checked)} onChange={e=>changeComponent(c.id,e.target.checked)} aria-label={`Компонент ${c.name}`} />
          <span className="componentInfo0247">
            <strong>{c.name} <small>{c.version||''}</small></strong>
            <small>{topologyLabel(c)||c.id}</small>
            {c.description&&<span>{c.description}</span>}
            <small>{[c.required?'Обязательный':null,c.limited?'Ограниченный':null,reasons.get(c.id),unavailableReason].filter(Boolean).join(' · ')}</small>
          </span>
        </label>;
      })}
    </div>
    {pending&&<section className="componentConfirm0247" role="region" aria-label="Подтверждение изменений компонентов">
      <h4>Предварительная проверка изменений</h4>
      {working&&<p role="status">NeverRuntime проверяет зависимости, условия и файлы…</p>}
      {error&&<p role="alert" className="error">Конфигурация заблокирована: {error}</p>}
      {preview&&diff&&<>
        <p>Компоненты: +{[...selectedNext].filter(x=>!selected.has(x)).length} / −{[...selected].filter(x=>!selectedNext.has(x)).length}.</p>
        <p>Файлы: добавить {diff.addedFiles.length}, убрать {diff.removedFiles.length}. Необходимо проверить или загрузить {diff.downloadFiles.length} файлов, до <strong>{formatBytes(diff.downloadBytesUpperBound)}</strong> без учёта кеша; общий объём выбранных файлов {formatBytes(diff.totalSelectedBytes)}.</p>
        <details><summary>Подробности diff и зависимости</summary>
          <p>Добавляемые компоненты: {[...selectedNext].filter(x=>!selected.has(x)).join(', ')||'нет'}</p>
          <p>Отключаемые компоненты: {[...selected].filter(x=>!selectedNext.has(x)).join(', ')||'нет'}</p>
          <p>Добавляемые файлы: {diff.addedFiles.join(', ')||'нет'}</p>
          <p>Удаляемые managed-файлы: {diff.removedFiles.join(', ')||'нет'}</p>
          <ul>{preview.reasons.map(r=><li key={r.id}>{r.id}: {r.reason}</li>)}</ul>
        </details>
        {(pending.removed.length>0||diff.removedFiles.length>0)&&<p className="componentWarning0247">Внимание: подтверждение заменит предыдущий выбор и может убрать компоненты/управляемые файлы. Неизвестные пользовательские файлы не удаляются.</p>}
        <small>Resolved plan: {diff.planSha256}</small>
      </>}
      <div className="toolbar inline">
        <button className="primary" disabled={working||installing||transferBusy||!preview||!diff||Boolean(error)} onClick={async()=>{
          if(!pending||!preview||!diff)return;
          setInstalling(true);setError('');
          try{await installSelection(pending.value);setPending(null);}
          catch(e){setError(String(e));}
          finally{setInstalling(false);}
        }}>{installing?'Установка…':'Подтвердить и установить'}</button>
        <button disabled={installing||transferBusy} onClick={()=>{setPending(null);setError('');}}>Отменить</button>
      </div>
    </section>}
  </article>;
}
