import React, {useRef,useState} from 'react';
import {readPng0355,signBranding0355,validateBrand0355,verifyBootstrap0355,type Branding0355} from './branding_0355';

const starter:Branding0355={displayName:'Project Launcher',publisher:'Project',accentColor:'#22c55e',backgroundColor:'#0f172a',textColor:'#e5e7eb',locale:'ru',news:[]};
function brandImage(data?:string){return data?`data:image/png;base64,${data}`:undefined}
export function BrandingStudio0355({projectId,canSign}:{projectId:string;canSign:boolean}){
  const privateInput=useRef<HTMLInputElement>(null);
  const [source,setSource]=useState('');const [root,setRoot]=useState('');const [policy,setPolicy]=useState('');
  const [loaded,setLoaded]=useState<{projectId:string;profileId:string;schema:string}|null>(null);
  const [brand,setBrand]=useState<Branding0355>(starter);const [seedFile,setSeedFile]=useState<File|null>(null);
  const [error,setError]=useState('');const [status,setStatus]=useState('');const [busy,setBusy]=useState(false);
  const change=(key:keyof Branding0355,value:string)=>{setBrand(b=>({...b,[key]:value}));setStatus('Изменения не подписаны');};
  async function choose(file:File|undefined,kind:'source'|'policy'){
    setError('');setStatus('');setLoaded(null);
    if(!file)return;
    if(file.size>(kind==='source'?1024*1024:128*1024))throw Error('Файл превышает допустимый размер');
    const value=await file.text();if(kind==='source')setSource(value);else setPolicy(value);
  }
  async function inspect(){
    setError('');setStatus('');
    const result=await verifyBootstrap0355(source,root.trim(),policy);
    if(result.payload.projectId!==projectId)throw Error(`Bootstrap принадлежит проекту ${result.payload.projectId}, а в панели выбран ${projectId}`);
    setBrand(result.payload.branding??{...starter,publisher:projectId,displayName:projectId});
    setLoaded({projectId:result.payload.projectId,profileId:result.payload.profileId,schema:result.envelope.schemaVersion});
    setStatus('Подпись исходного bundle проверена локально. Изменения доступны для предпросмотра.');
  }
  async function signedDownload(){
    if(!loaded||!canSign)throw Error('Подписывать bundle может только уполномоченный владелец проекта');
    if(loaded.projectId!==projectId)throw Error('Изменён контекст проекта: повторите проверку bundle');
    if(!seedFile||seedFile.size>4096)throw Error('Выберите небольшой локальный файл с 32-байтовым Ed25519 seed hex');
    setError('');setBusy(true);
    try{
      const seed=(await seedFile.text()).trim();
      const output=await signBranding0355(source,root.trim(),seed,brand,policy);
      const url=URL.createObjectURL(new Blob([output],{type:'application/json'}));
      try{const a=document.createElement('a');a.href=url;a.download='bootstrap.signed.json';a.click();}
      finally{setTimeout(()=>URL.revokeObjectURL(url),1000)}
      setSeedFile(null);if(privateInput.current)privateInput.current.value='';setStatus('Новый bootstrap проверен и сохранён. Замените им файл в подписываемом installer bundle; опубликуйте новый установщик.');
    }finally{setBusy(false)}
  }
  const previewValid=(()=>{try{validateBrand0355(brand);return true}catch{return false}})();
  return <section className="card wide brandingStudio0355">
    <h2>Branding Studio · 0.35.5</h2>
    <p className="muted">Предпросмотр меняется сразу. Исходный bootstrap проверяется Ed25519, новый подписывается в браузере. Ключ не передаётся в Backend и не сохраняется. Владелец затем помещает новый <code>bootstrap.signed.json</code> в распространяемый installer bundle.</p>
    <div className="formGrid">
      <article className="subcard">
        <h3>1. Подписанный bundle владельца</h3>
        <label className="field">Исходный bootstrap.signed.json<input type="file" accept=".json,application/json" onChange={e=>choose(e.target.files?.[0],'source').catch(e=>setError(String(e)))} /></label>
        <label className="field">Закреплённый root Ed25519 public key (64 hex)<input value={root} spellCheck={false} onChange={e=>{setRoot(e.target.value);setLoaded(null)}} /></label>
        <label className="field">Trust policy для delegated v2 (для v1 не выбирайте)<input type="file" accept=".json,application/json" onChange={e=>choose(e.target.files?.[0],'policy').catch(e=>setError(String(e)))} /></label>
        {policy&&<button onClick={()=>{setPolicy('');setLoaded(null)}}>Убрать trust policy</button>}
        <div className="buttonRow"><button disabled={!source||!root||!projectId} onClick={()=>inspect().catch(e=>{setLoaded(null);setError(String(e))})}>Проверить исходную подпись</button></div>
        {loaded&&<p className="success">Подпись проверена · проект {loaded.projectId} · профиль {loaded.profileId} · envelope {loaded.schema}</p>}
      </article>
      <article className="subcard">
        <h3>2. Оформление</h3>
        <label className="field">Название<input maxLength={80} value={brand.displayName} onChange={e=>change('displayName',e.target.value)}/></label>
        <label className="field">Издатель<input maxLength={96} value={brand.publisher} onChange={e=>change('publisher',e.target.value)}/></label>
        <label className="field">Сайт HTTPS<input value={brand.websiteUrl||''} onChange={e=>change('websiteUrl',e.target.value)}/></label>
        <div className="brandColors0355">
          {([['accentColor','Акцент'],['backgroundColor','Фон'],['textColor','Текст']] as const).map(([key,label])=><label key={key}>{label}<input aria-label={label} type="color" value={brand[key]||'#ffffff'} onChange={e=>change(key,e.target.value)}/></label>)}
        </div>
        <label className="field">Язык оформления<select value={brand.locale||'ru'} onChange={e=>change('locale',e.target.value)}><option value="ru">Русский</option><option value="en">English</option></select></label>
        {([['logoPng','Логотип'],['iconPng','Иконка в Desktop'],['splashPng','Фон splash']] as const).map(([field,label])=><label className="field" key={field}>{label} · PNG до 128 KiB
          <input type="file" accept="image/png" onChange={e=>{const f=e.target.files?.[0];if(f)readPng0355(f).then(s=>change(field,s)).catch(err=>setError(String(err)))}}/>
          {brand[field]&&<button type="button" onClick={()=>change(field,'')}>Удалить {label.toLowerCase()}</button>}
        </label>)}
        <h4>Новости и ссылки (до 5)</h4>
        {(brand.news||[]).map((news,index)=><div className="brandNewsEdit0355" key={index}>
          <input aria-label={`Заголовок ${index+1}`} maxLength={120} value={news.title} placeholder="Заголовок" onChange={e=>(setBrand(b=>({...b,news:b.news?.map((n,i)=>i===index?{...n,title:e.target.value}:n)})),setStatus('Изменения не подписаны'))}/>
          <input aria-label={`Ссылка ${index+1}`} value={news.url} placeholder="https://…" onChange={e=>(setBrand(b=>({...b,news:b.news?.map((n,i)=>i===index?{...n,url:e.target.value}:n)})),setStatus('Изменения не подписаны'))}/>
          <button onClick={()=>(setBrand(b=>({...b,news:b.news?.filter((_,i)=>i!==index)})),setStatus('Изменения не подписаны'))}>Удалить</button>
        </div>)}
        {(brand.news?.length||0)<5&&<button onClick={()=>(setBrand(b=>({...b,news:[...(b.news||[]),{title:'',url:''}]})),setStatus('Изменения не подписаны'))}>Добавить новость</button>}
      </article>
    </div>
    <article className="subcard brandPreviewWrapper0355">
      <h3>3. Live Preview · Desktop</h3>
      <div className="brandPreview0355" style={{backgroundColor:brand.backgroundColor||'#0f172a',color:brand.textColor||'#e5e7eb',borderColor:brand.accentColor||'#22c55e'}}>
        <aside>
          {brand.iconPng&&<img width={44} height={44} alt="Иконка" src={brandImage(brand.iconPng)} />}
          <strong>{brand.displayName}</strong><p>{brand.publisher}</p>
          <p>{brand.locale==='en'?'Home · Accounts · Servers':'Главная · Аккаунты · Серверы'}</p>
        </aside>
        <div className="brandPreviewMain0355" style={brand.splashPng?{backgroundImage:`linear-gradient(0deg,rgba(0,0,0,.6),rgba(0,0,0,.6)),url(${brandImage(brand.splashPng)})`}:{}}>
          {brand.logoPng&&<img className="brandPreviewLogo0355" alt="Логотип" src={brandImage(brand.logoPng)} />}
          <h2>{brand.displayName}</h2><p>{brand.locale==='en'?'Ready to play':'Готово к игре'}</p>
          <button style={{background:brand.accentColor||'#22c55e',color:brand.backgroundColor||'#0f172a'}}>{brand.locale==='en'?'Play':'Играть'}</button>
          <div>{(brand.news||[]).map((n,i)=><p key={i}>{n.title} · {n.url}</p>)}</div>
        </div>
      </div>
      {!previewValid&&<p className="error">Предпросмотр содержит некорректные данные; подписание заблокировано.</p>}
    </article>
    <article className="subcard">
      <h3>4. Подписание и экспорт</h3>
      <label className="field">Локальный файл приватного Ed25519 seed (32 байта hex)
        <input ref={privateInput} type="file" accept=".key,.txt" onChange={e=>setSeedFile(e.target.files?.[0]??null)}/>
      </label>
      <p className="muted">Для v1 нужен root seed, для v2 — seed активного делегированного bootstrap-ключа из загруженной trust policy. При несовпадении ключа подписание отклоняется.</p>
      <div className="buttonRow"><button disabled={!canSign||!loaded||!previewValid||!seedFile||busy} onClick={()=>signedDownload().catch(err=>setError(String(err)))}>{busy?'Подписание…':'Подписать и скачать bootstrap.signed.json'}</button></div>
      {status&&<p className="success" role="status">{status}</p>}
      {error&&<p className="error" role="alert">{error}</p>}
    </article>
  </section>;
}
