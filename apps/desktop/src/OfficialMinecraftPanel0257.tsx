import React, {useEffect, useState} from 'react';
import {OfficialMinecraftClient0257, type OfficialDevice0257, type OfficialProfile0257, type OfficialAccount0267, type NeverOfficialLink0268} from './official_minecraft_0257';

type Props = {
  client: OfficialMinecraftClient0257;
  linkedProfile: OfficialProfile0257 | null;
  onLinked: (profile: OfficialProfile0257 | null) => void;
};

export function OfficialMinecraftPanel0257({client, linkedProfile, onLinked}: Props) {
  const [device, setDevice] = useState<OfficialDevice0257 | null>(null);
  const [accounts, setAccounts] = useState<OfficialAccount0267[]>([]);
  const [neverLinks, setNeverLinks] = useState<NeverOfficialLink0268[] | null>(null);
  const [browserPending, setBrowserPending] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [variant, setVariant] = useState<'classic'|'slim'>('classic');
  const [file, setFile] = useState<File | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  useEffect(() => {
    if (!device) { setRemaining(null); return; }
    const until = Date.now() + device.expiresIn * 1000;
    const update = () => setRemaining(Math.max(0, Math.ceil((until - Date.now()) / 1000)));
    update();
    const timer = setInterval(update, 1000);
    return () => clearInterval(timer);
  }, [device]);
  useEffect(() => {
    let cancelled = false;
    void client.accounts().then(entries=>{if (!cancelled) setAccounts(entries);})
      .catch(e=>{if (!cancelled) setError(e instanceof Error?e.message:String(e));});
    void client.neverLinks().then(links=>{if (!cancelled) setNeverLinks(links);})
      .catch(()=>{if (!cancelled) setNeverLinks(null);});
    return () => {cancelled = true;};
  }, [client, linkedProfile?.id]);
  async function updateAccounts() {
    setAccounts(await client.accounts());
    try { setNeverLinks(await client.neverLinks()); }
    catch {setNeverLinks(null);}
  }
  async function completed(profile: OfficialProfile0257) {
    onLinked(profile);
    await updateAccounts();
  }
  async function beginDeviceLogin() {
    await perform(async () => {
      const challenge = await client.begin();
      setDevice(challenge);
      // Existing selected account remains active while adding a new one.
      // This command waits natively and applies provider pacing/slow_down.
      // It never exposes backend session tickets or device_code to React.
      void client.waitDevice().then(profile => {
        void completed(profile).catch(e=>setError(e instanceof Error?e.message:String(e)));
        setDevice(null);
      }).catch(e => {
        if (!(e instanceof Error && e.message.includes('отменена'))) {
          setError(e instanceof Error ? e.message : String(e));
          setDevice(null);
        }
      });
    });
  }
  async function perform(task: () => Promise<void>) {
    setBusy(true);setError('');
    try { await task(); } catch(e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  return <section className="panel">
    <h3>Официальный Minecraft (Microsoft)</h3>
    <p>Официальная учётная запись отдельна от локального профиля NeverLauncher. Доступны только скины и плащи, подтверждённые Minecraft Services.</p>
    <div className="toolbar inline">
      <button disabled={busy||browserPending} onClick={()=>{
        setBrowserPending(true);setError('');setDevice(null);
        void client.browserLogin().then(profile=>{void completed(profile).catch(e=>setError(String(e)));setDevice(null);}).catch(e=>{
          if (e instanceof Error && !e.message.includes('отменена')) setError(e.message);
        }).finally(()=>setBrowserPending(false));
      }}>Войти через браузер Microsoft (PKCE)</button>
      {browserPending && <>
        <span role="status">Завершите вход в открывшемся системном браузере.</span>
        <button onClick={()=>void perform(async()=>{await client.cancel();setDevice(null);})}>Отменить вход</button>
      </>}
      <button disabled={busy||browserPending} onClick={()=>void beginDeviceLogin()}>Device Code (резервный режим)</button>
      {device && <>
        <span>Код: <strong>{device.userCode}</strong></span>
        <a href={device.verificationUri} target="_blank" rel="noopener noreferrer">Открыть вход Microsoft</a>
        <span role="status">Вход проверяется автоматически. Интервалы Microsoft и slow_down соблюдаются.</span>
        {remaining !== null && <span>Осталось: {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, '0')}</span>}
        <button disabled={busy} onClick={()=>void perform(async()=>{await client.cancel();setDevice(null);})}>Отменить вход</button>
      </>}
    </div>
    {accounts.length > 0 && <div className="toolbar inline" aria-label="Официальные аккаунты Minecraft">
      <label htmlFor="officialAccount0267">Игровой аккаунт:</label>
      <select id="officialAccount0267" disabled={busy||browserPending||!!device}
        value={accounts.find(account=>account.active)?.id||''}
        onChange={e=>void perform(async()=>{await completed(await client.selectAccount(e.target.value));})}>
        {accounts.map(account=><option key={account.id} value={account.id}>{account.name} · {account.id.slice(0,8)}</option>)}
      </select>
      <button disabled={busy||browserPending||!!device||!linkedProfile} onClick={()=>void perform(async()=>{await completed(await client.refresh());})}>Обновить игровую сессию</button>
      {accounts.some(a=>a.active) && <button disabled={busy||browserPending||!!device} onClick={()=>void perform(async()=>{
        const active = accounts.find(account=>account.active);
        if (!active || !window.confirm(`Выйти из Minecraft-аккаунта ${active.name} на этом устройстве?`)) return;
        let next: OfficialProfile0257 | null = null;
        try { next = await client.logout(active.id); }
        finally { onLinked(next); await updateAccounts(); }
      })}>Выйти из выбранного аккаунта</button>}
    </div>}
    {linkedProfile && <div className="toolbar inline" aria-label="Связь Never и Minecraft">
      {!neverLinks ? <span>Связи Never недоступны. Проверьте Backend и базу данных.</span> :
      neverLinks.some(link=>link.minecraftUuid===linkedProfile.id.toLowerCase()) ? <>
        <span>Связан с Never identity (официальный UUID подтверждён Backend).</span>
        <button disabled={busy||browserPending||!!device} onClick={()=>void perform(async()=>{
          if (!window.confirm(`Отвязать Minecraft ${linkedProfile.name} (${linkedProfile.id}) от Never identity? Игровая сессия на устройстве сохранится.`))return;
          await client.unlinkFromNever(linkedProfile.id,true);
          await updateAccounts();
        })}>Отвязать от Never</button>
      </> : <>
        <span>Не привязан к Never identity. Наличие аккаунта в Desktop не означает привязку.</span>
        <button disabled={busy||browserPending||!!device} onClick={()=>void perform(async()=>{
          if (!window.confirm(`Привязать Never identity к официальному Minecraft ${linkedProfile.name} (${linkedProfile.id})? Будут проверены Never-сессия и владение Minecraft у Mojang.`))return;
          await client.linkToNever(linkedProfile.id,true);
          await updateAccounts();
        })}>Привязать к Never</button>
      </>}
    </div>}
    {linkedProfile && <>
      <p>Профиль: <strong>{linkedProfile.name}</strong> · UUID: <code>{linkedProfile.id}</code></p>
      <div className="toolbar inline">
        <button disabled={busy} onClick={()=>void perform(async()=>onLinked(await client.profile()))}>Обновить профиль</button>
      </div>
      <div className="toolbar inline">
        <input type="file" accept="image/png" aria-label="Официальный скин PNG" onChange={e=>setFile(e.target.files?.[0]||null)}/>
        <select value={variant} onChange={e=>setVariant(e.target.value as 'classic'|'slim')} aria-label="Модель скина"><option value="classic">Classic</option><option value="slim">Slim</option></select>
        <button disabled={!file||busy} onClick={()=>void perform(async()=>{if(file)onLinked(await client.uploadSkin(file,variant));})}>Загрузить официальный скин</button>
        <button disabled={busy} onClick={()=>void perform(async()=>onLinked(await client.resetSkin()))}>Сбросить скин</button>
      </div>
      <div className="toolbar inline">
        <span>Плащи аккаунта:</span>
        {(linkedProfile.capes || []).map(cape=><button key={cape.id} disabled={busy} onClick={()=>void perform(async()=>onLinked(await client.selectCape(cape.id)))}>{cape.alias||cape.id}{cape.state==='ACTIVE'?' (выбран)':''}</button>)}
        <button disabled={busy} onClick={()=>void perform(async()=>onLinked(await client.resetCape()))}>Снять плащ</button>
      </div>
    </>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
