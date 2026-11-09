import React, { useState } from 'react';
import {guardCandidate05011,guardCandidateAllowed05011,verifyGuardEnvelope05011,type GuardContent05011} from './guard_policy_offline_05011';

function download05011(file:string,value:string){
 const blob=new Blob([value],{type:'application/json'});const url=URL.createObjectURL(blob);
 try{const a=document.createElement('a');a.href=url;a.download=file;a.click();}finally{setTimeout(()=>URL.revokeObjectURL(url),1000)}
}
export function GuardPolicyOperations05011({canOperate}:{canOperate:boolean}){
 const [publicKey,setPublicKey]=useState('');
 const [current,setCurrent]=useState<GuardContent05011|null>(null);
 const [old,setOld]=useState<GuardContent05011|null>(null);
 const [candidate,setCandidate]=useState<GuardContent05011|null>(null);
 const [verifiedSigned,setVerifiedSigned]=useState('');
 const [digest,setDigest]=useState('');
 const [transforms,setTransforms]=useState('');
 const [diagnostic,setDiagnostic]=useState<Record<string,unknown>|null>(null);
 const [error,setError]=useState('');const [status,setStatus]=useState('');
 const changeKey=(value:string)=>{setPublicKey(value);setCurrent(null);setOld(null);setCandidate(null);setVerifiedSigned('');setStatus('');};
 async function chooseEnvelope(file:File|undefined,kind:'current'|'history'|'candidate'){
  if(!file)return;
  setError('');setStatus('');
  if(file.size>256*1024)throw Error('Подписанный пакет политики Guard слишком большой');
  const raw=await file.text();const policy=await verifyGuardEnvelope05011(raw,publicKey,Math.floor(Date.now()/1000),kind!=="candidate");
  if(kind==='current'){setCurrent(policy);setCandidate(null);setVerifiedSigned('');setOld(null)}
  if(kind==='history'){if(!current)throw Error('Сначала проверьте текущую политику');if(policy.epoch>=current.epoch)throw Error('Выберите более старую политику');setOld(policy)}
  if(kind==='candidate'){
   if(!current)throw Error('Сначала проверьте текущую политику');
   guardCandidateAllowed05011(current,policy);
   setVerifiedSigned(raw);
  }
  setStatus('Подпись Ed25519 проверена локально; установка на игровых машинах не выполнялась');
 }
 function draft(restore:boolean){
  if(!canOperate)throw Error('Для подготовки изменений необходимы права управления настройками');
  if(!current)throw Error('Сначала проверьте текущую политику');
  if(restore&&!old)throw Error('Для отката требуется ранее подписанная политика');
  const next=guardCandidate05011(current,restore?old:null,digest,transforms);
  setCandidate(next);setVerifiedSigned('');
  download05011(`guard-${restore?'rollback':'revoke'}-epoch-${next.epoch}.json`,JSON.stringify(next,null,2)+'\n');
  setStatus(`Создана НЕПОДПИСАННАЯ политика эпохи ${next.epoch}. Подпишите её автономной утилитой guard-policy-sign и проверьте перед установкой.`);
 }
 return <section className="subcard" aria-label="Операции с политиками Guard 0.50.11">
  <h3>Guard · подписанные политики и восстановление</h3>
  <p>Проверка подписи выполняется в браузере по внешнему закреплённому публичному ключу. Приватный ключ не загружается. Admin готовит изменения и проверяет результат; применение на защищённом клиенте выполняет CLI.</p>
  <label className="field">Публичный ключ Ed25519 (64 шестнадцатеричных символа из внешнего доверенного источника)<input spellCheck={false} autoComplete="off" value={publicKey} onChange={e=>changeKey(e.target.value.trim())}/></label>
  <div className="formGrid">
   <label className="field">Текущая подписанная политика<input type="file" accept=".json,application/json" onChange={e=>chooseEnvelope(e.target.files?.[0],'current').catch(err=>setError(String(err)))}/></label>
   <label className="field">Предыдущая подписанная политика для отката<input type="file" accept=".json,application/json" disabled={!current} onChange={e=>chooseEnvelope(e.target.files?.[0],'history').catch(err=>setError(String(err)))}/></label>
  </div>
  {current&&current.expiresAt<=Math.floor(Date.now()/1000)&&<p role="alert">Срок политики истёк: её нельзя использовать для запуска, но допустимо подписать новую более высокую эпоху.</p>}
  {current&&<p>Проверена подпись эпохи <strong>{current.epoch}</strong>; проект {current.projectId}; Minecraft {current.minecraft}; загрузчик {current.loader === 'vanilla' ? 'без загрузчика' : current.loader}; до {new Date(current.expiresAt*1000).toLocaleString("ru-RU")}; модулей {current.artifacts.length}; отозванных хешей {current.revokedDigests.length}.</p>}
  {old&&<p>Историческая эпоха {old.epoch}, к восстановлению допускаются только неизменённые ранее утверждённые компоненты.</p>}
  <label className="field">Отозвать SHA-256 JAR/native (через запятую)<textarea value={digest} rows={2} onChange={e=>setDigest(e.target.value)} disabled={!canOperate}/></label>
  <label className="field">Отозвать перехватчики JVM (по одному ID в строке)<textarea value={transforms} rows={2} onChange={e=>setTransforms(e.target.value)} disabled={!canOperate}/></label>
  <div className="buttonRow">
   <button disabled={!current||!canOperate} onClick={()=>{try{draft(false)}catch(e){setError(String(e))}}}>Подготовить отзыв</button>
   <button disabled={!old||!current||!canOperate} onClick={()=>{try{draft(true)}catch(e){setError(String(e))}}}>Подготовить безопасный откат</button>
  </div>
  {candidate&&<p>Политика эпохи {candidate.epoch} требует новой внешней подписи Ed25519. После подписания загрузите готовый пакет для проверки:</p>}
  <label className="field">Новый подписанный конверт<input type="file" accept=".json,application/json" disabled={!current} onChange={e=>chooseEnvelope(e.target.files?.[0],'candidate').catch(err=>setError(String(err)))}/></label>
  {verifiedSigned&&<div className="buttonRow"><button onClick={()=>download05011('guard-policy-verified.signed.json',verifiedSigned)}>Сохранить проверенный подписанный пакет для командной строки</button></div>}
  <h4>Диагностика установленной политики защиты</h4>
  <p>Загрузите отчёт команды <code>launcher runtime client-factory guard-policy-diagnose</code>; он не отправляется на сервер.</p>
  <input type="file" accept=".json,application/json" onChange={e=>{const file=e.target.files?.[0];if(!file)return;if(file.size>64*1024){setError('Диагностика слишком велика');return}void file.text().then(t=>{const d=JSON.parse(t) as Record<string,unknown>;if(d.operation!=='guard-policy-diagnose')throw Error('Это не отчёт защиты');setDiagnostic(d);setError('')}).catch(err=>setError(String(err)))}}/>
  {diagnostic&&<pre>{JSON.stringify({status:diagnostic.status,reason:diagnostic.reason,detail:diagnostic.detail,epoch:diagnostic.epoch,verifiedArtifacts:diagnostic.verifiedArtifacts,verifiedExternalNative:diagnostic.verifiedExternalNative},null,2)}</pre>}
  {status&&<p role="status">{status}</p>}{error&&<p role="alert" className="error">{error}</p>}
  <p><strong>Установка:</strong> <code>launcher runtime client-factory guard-policy-install --client-dir CLIENT --public-key PUBLIC --policy SIGNED</code>. Для отката используйте <code>guard-policy-rollback</code> с вновь подписанной более высокой эпохой. Установка не обходит защиту от отката.</p>
 </section>
}
