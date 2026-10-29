import React, {useEffect, useState} from 'react';
import {requestJSON, ApiError, IndeterminateApiError} from '../api/client';
import type {Profile} from '../api/admin';
import {validateProfile0382} from './profile-launch-0382';

type Fields = {id:string;name:string;description:string;loader:string;preset:string;isDefault:boolean;minecraftVersion:string;loaderVersion:string;javaMajor:number};
type Snapshot = {schemaVersion:string;revision:number;digest:string;spec:Fields};
const blank = ():Fields=>({id:'',name:'',description:'',loader:'vanilla',loaderVersion:'',minecraftVersion:'',javaMajor:17,preset:'',isDefault:false});
const fromProfile = (p:Profile):Fields=>({id:p.id,name:p.name,description:p.description||'',loader:p.loader||'vanilla',loaderVersion:p.loaderVersion||'',minecraftVersion:p.minecraftVersion||'',javaMajor:p.javaMajor||17,preset:p.preset||'',isDefault:p.isDefault});
export function ProfileEditor0382({backendUrl,token,projectId,selectedProfile,onChanged,onCreated}: {
  backendUrl:string;token:string;projectId:string;selectedProfile?:Profile;onChanged:()=>Promise<void>;onCreated:(id:string)=>void;
}) {
  const [form,setForm]=useState<Fields>(blank);
  const [baseRevision,setBaseRevision]=useState<number|null>(null);
  const [history,setHistory]=useState<Snapshot[]>([]);
  const [restoreRevision,setRestoreRevision]=useState('');
  const [working,setWorking]=useState(false);
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');
  const [dirty,setDirty]=useState(false);
  const root=`/api/v1/admin/projects/${encodeURIComponent(projectId)}/profiles`;
  useEffect(()=>{
    setForm(selectedProfile?fromProfile(selectedProfile):blank());setBaseRevision(selectedProfile?.revision??null);
    setDirty(false);setHistory([]);setRestoreRevision('');setError('');setNotice('');
  },[projectId,selectedProfile?.id]);
  useEffect(()=>{
    let current=true;
    if(!projectId || !selectedProfile)return;
    requestJSON<{items:Snapshot[]}>(backendUrl,`/api/v1/projects/${encodeURIComponent(projectId)}/profiles/${encodeURIComponent(selectedProfile.id)}/revisions`,token)
      .then(v=>{if(current)setHistory(v.items||[])}).catch(e=>{if(current)setError(`История профиля: ${e instanceof Error?e.message:String(e)}`)});
    return()=>{current=false};
  },[backendUrl,token,projectId,selectedProfile?.id,selectedProfile?.revision]);
  const edit=<K extends keyof Fields>(key:K,value:Fields[K])=>{setForm(old=>({...old,[key]:value}));setDirty(true);setError('');setNotice('')};
  async function submit(){
    const problem=validateProfile0382(form);if(problem){setError(problem);return}
    if(working || !projectId)return;
    const editing=!!selectedProfile;
    if(editing && (!baseRevision || form.id!==selectedProfile.id)){setError('ID существующего профиля неизменяем. Для нового ID используйте клонирование.');return}
    setWorking(true);setError('');setNotice('');
    try{
      const result=await requestJSON<{profile:Profile}>(backendUrl,editing?`${root}/${encodeURIComponent(selectedProfile.id)}`:root,token,
        {method:editing?'PATCH':'POST',body:JSON.stringify({...form,loaderVersion:form.loader==='vanilla'?'':form.loaderVersion,...(editing?{expectedRevision:baseRevision}:{})})});
      if(!result.profile?.id)throw new Error('Backend не вернул сохранённый профиль. Проверьте список перед повтором.');
      setDirty(false);setBaseRevision(result.profile.revision);setForm(fromProfile(result.profile));
      if(!editing)onCreated(result.profile.id);
      setNotice(`Профиль ${result.profile.id} сохранён. Ревизия ${result.profile.revision}.`);
      try { await onChanged(); } catch (reloadError) {
        setNotice(`Профиль ${result.profile.id} сохранён (ревизия ${result.profile.revision}). Не удалось обновить список: ${reloadError instanceof Error?reloadError.message:String(reloadError)}. Обновите страницу; повторять создание не требуется.`);
      }
    }catch(e){
      if(e instanceof ApiError && e.status===409)setError('Ревизия уже изменилась. Скопируйте свои изменения и обновите профиль перед повтором.');
      else if(e instanceof IndeterminateApiError)setError(e.message);
      else setError(e instanceof Error?e.message:String(e));
    }finally{setWorking(false)}
  }
  function restore(){
    const snapshot=history.find(h=>String(h.revision)===restoreRevision);
    if(!snapshot || !selectedProfile || !window.confirm(`Загрузить поля ревизии ${snapshot.revision} в редактор? Они будут записаны новой ревизией только после сохранения.`))return;
    setForm({...fromProfile(selectedProfile),...snapshot.spec,id:selectedProfile.id,
      minecraftVersion:snapshot.spec.minecraftVersion||'',loaderVersion:snapshot.spec.loaderVersion||'',javaMajor:snapshot.spec.javaMajor||17});
    setDirty(true);setNotice(snapshot.spec.minecraftVersion
      ?'Исторические значения загружены. Нажмите «Сохранить изменения».'
      :'У старой ревизии не было закреплённых параметров запуска. Укажите Minecraft, loader и Java перед сохранением.');
  }
  const issue=validateProfile0382(form);
  return <article className="subcard" aria-label="Редактор профиля Minecraft">
    <h3>{selectedProfile?`Настройка профиля ${selectedProfile.id}`:'Создать профиль Minecraft'}</h3>
    <p className="muted">Minecraft, загрузчик и Java сохраняются на Backend и входят в неизменяемую ревизию профиля. Уже опубликованные сборки не изменяются.</p>
    <div className="formGrid">
      <label className="field">ID профиля<input disabled={working||!!selectedProfile} value={form.id} onChange={e=>edit('id',e.target.value.trim())} placeholder="survival" /></label>
      <label className="field">Название<input disabled={working} value={form.name} onChange={e=>edit('name',e.target.value)} /></label>
      <label className="field">Minecraft<input disabled={working} value={form.minecraftVersion} onChange={e=>edit('minecraftVersion',e.target.value.trim())} placeholder="1.21.1" /></label>
      <label className="field">Загрузчик<select disabled={working} value={form.loader} onChange={e=>{edit('loader',e.target.value);if(e.target.value==='vanilla')edit('loaderVersion','')}}>
        {['vanilla','fabric','quilt','forge','neoforge'].map(loader=><option key={loader} value={loader}>{loader}</option>)}
      </select></label>
      {form.loader!=='vanilla'&&<label className="field">Точная версия загрузчика<input disabled={working} value={form.loaderVersion} onChange={e=>edit('loaderVersion',e.target.value.trim())} placeholder="Без latest" /></label>}
      <label className="field">Java major<input disabled={working} type="number" min="8" max="255" value={form.javaMajor} onChange={e=>edit('javaMajor',Number(e.target.value))} /></label>
      <label className="field">Пресет компонентов<input disabled={working} value={form.preset} onChange={e=>edit('preset',e.target.value)} /></label>
      <label className="field">Описание<textarea disabled={working} rows={3} value={form.description} onChange={e=>edit('description',e.target.value)} /></label>
    </div>
    <label className="check"><input disabled={working} type="checkbox" checked={form.isDefault} onChange={e=>edit('isDefault',e.target.checked)} />Профиль по умолчанию</label>
    {selectedProfile && <p className="muted">Редактируемая ревизия: <strong>{baseRevision??'—'}</strong> · digest: <code>{selectedProfile.digest||'—'}</code></p>}
    {selectedProfile && baseRevision !== null && selectedProfile.revision!==baseRevision &&
      <p role="alert" className="error">Профиль был изменён другим оператором (текущая ревизия {selectedProfile.revision}). Ваши изменения сохранены в форме, но для записи необходимо обновить профиль и применить изменения поверх новой ревизии.</p>}
    {issue && <p className="muted" role="status">{issue}</p>}
    <div className="buttonRow"><button disabled={working||!!issue||!projectId||!!selectedProfile&&!dirty} onClick={()=>void submit()}>{working?'Сохранение…':selectedProfile?'Сохранить новую ревизию':'Создать профиль'}</button>
      {selectedProfile && <button disabled={working||!dirty} onClick={()=>{setForm(fromProfile(selectedProfile));setBaseRevision(selectedProfile.revision);setDirty(false);setError('');setNotice('')}}>Отменить изменения</button>}
    </div>
    {selectedProfile && <section aria-label="История ревизий профиля">
      <h4>Ревизии профиля</h4><p className="muted">Восстановление не перезаписывает историю: при сохранении создаётся новая ревизия с CAS.</p>
      <label className="field">Ревизия для восстановления<select value={restoreRevision} disabled={working} onChange={e=>setRestoreRevision(e.target.value)}><option value="">Выберите ревизию</option>{history.map(h=><option key={h.revision} value={h.revision}>r{h.revision} · {h.spec.minecraftVersion||'без версии'} · {h.spec.loader} · Java {h.spec.javaMajor||'не задана'}</option>)}</select></label>
      <button disabled={working||!restoreRevision} onClick={restore}>Загрузить ревизию в редактор</button>
    </section>}
    {notice && <p role="status" className="success">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </article>
}
