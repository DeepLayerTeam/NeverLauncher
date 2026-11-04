import React, { useCallback, useEffect, useState } from 'react';
import { requestJSON } from '../api/client';

type Notice = { id: string; body: string; createdAt: string; expiresAt: string };
export function BackendNoticeInbox0289({backendUrl,token}: {backendUrl:string;token:string}) {
 const [items,setItems] = useState<Notice[]>([]);
 const [error,setError] = useState('');
 const load = useCallback(async()=>{
  const result=await requestJSON<{items:Notice[]}>(backendUrl,'/api/v1/backend/notices',token);
  setItems(result.items ?? []);setError('');
 },[backendUrl,token]);
 useEffect(()=>{
  let alive=true;
  const poll=()=>{void load().catch(e=>{if(alive)setError(String(e));});};
  poll();const timer=window.setInterval(poll,30000);
  return ()=>{alive=false;window.clearInterval(timer);};
 },[load]);
 async function ack(id:string){
  try{await requestJSON(backendUrl,`/api/v1/backend/notices/${encodeURIComponent(id)}/ack`,token,{method:'POST'});await load();setError('');}
  catch(e){setError(String(e));}
 }
 if(items.length===0 && !error)return null;
 return <section className="card wide" aria-label="Уведомления Backend">
  <h3>Уведомления Backend ({items.length})</h3>
  {items.map(it=><article key={it.id} className="subcard"><p>{it.body}</p><small className="muted">{it.createdAt} · до {it.expiresAt}</small><div className="buttonRow"><button onClick={()=>void ack(it.id)}>Подтвердить получение</button></div></article>)}
  {error && <p className="error" role="alert">Уведомления недоступны: {error}</p>}
 </section>;
}
