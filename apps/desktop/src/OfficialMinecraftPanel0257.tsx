import React, {useEffect, useRef, useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {OfficialMinecraftClient0257, type OfficialProfile0257} from './official_minecraft_0257';
import {AuthenticationExperience02610, initialAuthenticationState02610, type AuthenticationState02610} from './official_auth_experience_02610';

type Props = {
  client:OfficialMinecraftClient0257;
  linkedProfile:OfficialProfile0257|null;
  onLinked:(profile:OfficialProfile0257|null)=>void;
};
const formatTime=(seconds:number):string=>`${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')}`;

/** Complete account experience. Only metadata is retained by React; secrets stay in Rust. */
export function OfficialMinecraftPanel0257({client,linkedProfile,onLinked}:Props) {
  const [state,setState]=useState<AuthenticationState02610>(initialAuthenticationState02610);
  const [now,setNow]=useState(Date.now());
  const [skin,setSkin]=useState<File|null>(null);
  const [variant,setVariant]=useState<'classic'|'slim'>('classic');
  const controller=useRef<AuthenticationExperience02610|null>(null);
  const callback=useRef(onLinked);
  callback.current=onLinked;
  useEffect(()=>{
    const manager=new AuthenticationExperience02610(client,profile=>callback.current(profile));
    controller.current=manager;
    const unsubscribe=manager.subscribe(setState);
    void manager.initialize();
    return ()=>{unsubscribe();manager.dispose();if(controller.current===manager)controller.current=null;};
  },[client]);
  useEffect(()=>{setSkin(null);},[state.profile?.id]);
  useEffect(()=>{
    if(!state.deviceExpiresAt)return;
    const timer=window.setInterval(()=>setNow(Date.now()),1000);
    setNow(Date.now());
    return ()=>window.clearInterval(timer);
  },[state.deviceExpiresAt]);
  const call=(action:(manager:AuthenticationExperience02610)=>Promise<void>)=>{
    const manager=controller.current;
    if(manager)void action(manager);
  };
  const busy=state.activity!==null;
  const loginActive=state.activity==='browser'||state.activity==='device';
  const loading=state.activity==='loading';
  const profile=state.profile;
  const selected=state.accounts.find(account=>account.active);
  const linked=Boolean(profile && state.links?.some(link=>link.minecraftUuid.toLowerCase()===profile.id.toLowerCase()));
  const remaining=state.deviceExpiresAt?Math.max(0,Math.ceil((state.deviceExpiresAt-now)/1000)):0;
  const ready=Boolean(profile && selected?.id.toLowerCase()===profile.id.toLowerCase());
  const reauthRequired=Boolean(selected && !profile && !loading && !loginActive);

  return <section className="panel officialAuth02610" aria-label="Управление официальными Minecraft-аккаунтами">
    <div className="officialAuthHeader02610">
      <div><h3>Официальный Minecraft</h3><p>Вход в игру через Microsoft, отдельно от учётной записи Never. Токены сохраняются только в системном хранилище.</p></div>
      <span className={`officialAuthStatus02610 ${ready?'ready':reauthRequired?'warning':''}`} role="status">
        {loading?'Проверка сохранённой сессии…':ready?'Профиль подтверждён':reauthRequired?'Требуется повторная проверка':'Нет активной игровой сессии'}
      </span>
    </div>

    {state.issue && <div className="officialAuthError02610" role="alert">
      {state.issue}
      {!busy && <button type="button" onClick={()=>call(m=>m.initialize())}>Повторить проверку</button>}
    </div>}

    <div className="officialAuthSection02610">
      <div className="officialAuthSectionHeader02610"><h4>Игровые аккаунты</h4><span>{state.accounts.length} / 16</span></div>
      {!loading && state.accounts.length===0 && <p>Аккаунтов пока нет. Войдите через системный браузер Microsoft или используйте резервный Device Code.</p>}
      <div className="officialAuthAccounts02610" role="group" aria-label="Сохранённые аккаунты Minecraft">
        {state.accounts.map(account=><div key={account.id} className={`officialAuthAccount02610 ${account.active?'selected':''}`}>
          <div className="officialAuthAccountInfo02610">
            <strong>{account.name}</strong>
            <code title={account.id}>{account.id}</code>
            <small>{account.active?(ready?'Выбран · готов к запуску':'Выбран · нужна проверка'):'Сохранён в OS vault'}</small>
          </div>
          <div className="officialAuthAccountActions02610">
            <button type="button" disabled={busy||account.active} onClick={()=>call(m=>m.select(account.id))}
              aria-label={`Выбрать аккаунт ${account.name}`}>{account.active?'Выбран':'Выбрать'}</button>
            <button type="button" className="danger" disabled={busy} onClick={()=>{
              if(window.confirm(`Удалить локальную игровую сессию ${account.name} (${account.id})? Привязка к Never не будет удалена.`))call(m=>m.logout(account.id));
            }} aria-label={`Выйти из аккаунта ${account.name}`}>Выйти</button>
          </div>
        </div>)}
      </div>
      {state.accounts.length<16 && !loginActive && <div className="toolbar inline" role="group" aria-label="Добавить игровой аккаунт">
        <button className="primary" type="button" disabled={busy} onClick={()=>call(m=>m.browserLogin())}>{state.accounts.length?'Добавить через Microsoft':'Войти через Microsoft'}</button>
        <button type="button" disabled={busy} onClick={()=>call(m=>m.deviceLogin())}>Device Code</button>
      </div>}
      {state.accounts.length===16 && !loginActive && <p>Достигнут лимит 16 аккаунтов. Удалите неиспользуемый аккаунт, чтобы добавить новый.</p>}
      {loginActive && <div className="officialAuthLogin02610" role="group" aria-label="Вход Microsoft">
        {state.activity==='browser' ? <p role="status">Завершите вход в системном браузере. NeverLauncher ожидает защищённый callback.</p> : <>
          {!state.device ? <p role="status">Запрашиваем код у Microsoft…</p> : <>
            <p>Откройте Microsoft и введите код:</p>
            <div className="officialAuthDevice02610"><code aria-label="Код входа">{state.device.userCode}</code><button type="button" onClick={()=>{if(state.device && navigator.clipboard)void navigator.clipboard.writeText(state.device.userCode).catch(()=>{});}}>Копировать код</button></div>
            <a href={state.device.verificationUri} onClick={(event)=>{event.preventDefault();void invoke('open_external_https_0356',{url:state.device!.verificationUri}).catch(()=>{});}}>Открыть страницу входа Microsoft</a>
            <p role="status">Проверка автоматическая · осталось {formatTime(remaining)}. Не закрывайте лаунчер.</p>
          </>}
        </>}
        <button type="button" className="danger" onClick={()=>call(m=>m.cancelLogin())}>Отменить вход</button>
      </div>}
      {state.activity && !loginActive && !loading && <p role="status" aria-live="polite">{({cancel:'Отменяем вход',select:'Проверяем выбранный аккаунт',refresh:'Обновляем Microsoft и Minecraft токены',logout:'Удаляем игровую сессию',profile:'Проверяем профиль Minecraft',link:'Проверяем привязку Never',unlink:'Отвязываем от Never',skin:'Обновляем скин Minecraft',cape:'Обновляем плащ Minecraft'} as Record<string,string>)[state.activity]}…</p>}
    </div>

    <div className="officialAuthSection02610">
      <div className="officialAuthSectionHeader02610"><h4>Активная игровая сессия</h4>{ready && <span>Official Java Edition</span>}</div>
      {ready && profile ? <>
        <p><strong>{profile.name}</strong> · UUID: <code>{profile.id}</code></p>
        <div className="toolbar inline">
          <button disabled={busy} type="button" onClick={()=>call(m=>m.revalidate())}>Проверить профиль и доступ</button>
          <button disabled={busy} type="button" onClick={()=>call(m=>m.refresh())}>Обновить игровую сессию</button>
          <button disabled={busy} type="button" onClick={()=>call(m=>m.browserLogin())}>Войти заново</button>
        </div>
      </> : <>
        <p>{reauthRequired?'Проверка сохранённой сессии не завершилась успешно. Официальный запуск недоступен до нового подтверждения Minecraft profile.':'Выберите или добавьте аккаунт, чтобы запустить официальный Minecraft.'}</p>
        {reauthRequired && <div className="toolbar inline"><button disabled={busy} onClick={()=>call(m=>m.revalidate())}>Повторить проверку</button><button disabled={busy} onClick={()=>call(m=>m.browserLogin())}>Войти заново через Microsoft</button></div>}
      </>}
    </div>

    {ready && profile && <>
      <div className="officialAuthSection02610">
        <div className="officialAuthSectionHeader02610"><h4>Связь с Never identity</h4><span>{linked?'Привязан':state.links?'Не привязан':'Нет данных'}</span></div>
        {state.links===null ? <p>{state.linksIssue||'Проверяем связь с Never identity.'}</p> :
          <p>{linked?'Minecraft UUID подтверждён сервером Never.':'Локальный игровой аккаунт не привязан к Never identity.'}</p>}
        <div className="toolbar inline">
          {state.links!==null && (linked ?
            <button disabled={busy} onClick={()=>{
              if(window.confirm(`Отвязать ${profile.name} (${profile.id}) от Never? Локальная игровая сессия останется.`))call(m=>m.unlink(profile.id));
            }}>Отвязать от Never</button> :
            <button disabled={busy} onClick={()=>{
              if(window.confirm(`Привязать Never identity к ${profile.name} (${profile.id})? Backend проверит владение Minecraft.`))call(m=>m.link(profile.id));
            }}>Привязать к Never</button>)}
        </div>
      </div>
      <div className="officialAuthSection02610">
        <h4>Скин и плащ</h4>
        <div className="toolbar inline">
          <input type="file" accept="image/png" aria-label="Официальный скин PNG" onChange={e=>setSkin(e.target.files?.[0]||null)}/>
          <select value={variant} aria-label="Модель скина" onChange={e=>setVariant(e.target.value as 'classic'|'slim')}>
            <option value="classic">Classic</option><option value="slim">Slim</option>
          </select>
          <button disabled={busy||!skin} onClick={()=>{if(skin)call(m=>m.uploadSkin(skin,variant));}}>Загрузить скин</button>
          <button disabled={busy} onClick={()=>call(m=>m.resetSkin())}>Сбросить скин</button>
        </div>
        <div className="toolbar inline">
          {(profile.capes||[]).map(cape=><button key={cape.id} disabled={busy||cape.state==='ACTIVE'} onClick={()=>call(m=>m.selectCape(cape.id))}>{cape.alias||cape.id}{cape.state==='ACTIVE'?' (выбран)':''}</button>)}
          <button disabled={busy} onClick={()=>call(m=>m.resetCape())}>Снять плащ</button>
        </div>
      </div>
    </>}
    {/* Parent launch mode is driven solely by the verified profile callback, never by stored metadata. */}
    {linkedProfile && !ready && <p className="officialAuthError02610">Данные о ранее активном аккаунте перепроверяются. Официальный запуск временно недоступен.</p>}
  </section>;
}
