import React, {useState} from 'react';
import {OfficialMinecraftClient0257, type OfficialDevice0257, type OfficialProfile0257} from './official_minecraft_0257';

type Props = {
  client: OfficialMinecraftClient0257;
  linkedProfile: OfficialProfile0257 | null;
  onLinked: (profile: OfficialProfile0257 | null) => void;
};

export function OfficialMinecraftPanel0257({client, linkedProfile, onLinked}: Props) {
  const [device, setDevice] = useState<OfficialDevice0257 | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [variant, setVariant] = useState<'classic'|'slim'>('classic');
  const [file, setFile] = useState<File | null>(null);
  async function perform(task: () => Promise<void>) {
    setBusy(true);setError('');
    try { await task(); } catch(e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  return <section className="panel">
    <h3>Официальный Minecraft (Microsoft)</h3>
    <p>Официальная учётная запись отдельна от локального профиля NeverLauncher. Доступны только скины и плащи, подтверждённые Minecraft Services.</p>
    {!linkedProfile && <div className="toolbar inline">
      <button disabled={busy} onClick={()=>void perform(async()=>{const d=await client.begin();setDevice(d);onLinked(null);})}>Подключить Microsoft</button>
      {device && <>
        <span>Код: <strong>{device.userCode}</strong></span>
        <a href={device.verificationUri} target="_blank" rel="noopener noreferrer">Открыть вход Microsoft</a>
        <button disabled={busy} onClick={()=>void perform(async()=>{const p=await client.poll();if(p.profile){onLinked(p.profile);setDevice(null);}})}>Проверить вход</button>
      </>}
    </div>}
    {linkedProfile && <>
      <p>Профиль: <strong>{linkedProfile.name}</strong> · UUID: <code>{linkedProfile.id}</code></p>
      <div className="toolbar inline">
        <button disabled={busy} onClick={()=>void perform(async()=>onLinked(await client.profile()))}>Обновить профиль</button>
        <button disabled={busy} onClick={()=>{client.clear();onLinked(null);setDevice(null);}}>Отключить официальный аккаунт</button>
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
